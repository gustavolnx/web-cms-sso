const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const cors = require("cors");
const path = require("path");
const dotenv = require("dotenv");
const expressLayouts = require("express-ejs-layouts");
const methodOverride = require("method-override");
const flash = require("connect-flash");
const fileUpload = require("express-fileupload");
const passport = require("passport");

// Carrega as variáveis de ambiente
dotenv.config();

// Inicializa o Express
const app = express();

// Configuração para verificação de status online dos players
const OFFLINE_THRESHOLD_MINUTES = 2; // Tempo em minutos sem ping para considerar um player offline
let checkPlayersStatusInterval = null;

// Função para verificar o status dos players e marcar como offline aqueles que não enviam ping
async function checkPlayersStatus() {
  try {
    const Player = require("./models/player.model");

    // Tempo limite para considerar um player offline (2 minutos sem ping)
    const offlineThreshold = new Date();
    offlineThreshold.setMinutes(
      offlineThreshold.getMinutes() - OFFLINE_THRESHOLD_MINUTES
    );

    // Buscar players marcados como online mas com última conexão anterior ao limite
    const playersToUpdate = await Player.find({
      status: "online",
      last_connection: { $lt: offlineThreshold },
    });

    if (playersToUpdate.length > 0) {
      console.log(
        `Marcando ${playersToUpdate.length} player(s) como offline por inatividade`
      );

      // Atualizar status para offline
      await Player.updateMany(
        { _id: { $in: playersToUpdate.map((p) => p._id) } },
        { $set: { status: "offline" } }
      );
    }
  } catch (error) {
    console.error("Erro ao verificar status dos players:", error);
  }
}

// Configuração do middleware
app.use(
  cors({
    origin: "*", // Permitindo acesso de qualquer origem
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
// Rota específica para a pasta .well-known
app.use(
  "/.well-known",
  express.static(path.join(__dirname, "public", ".well-known"))
);

// Configuração do express-fileupload
/*
app.use(
  fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    useTempFiles: true,
    tempFileDir: "/tmp/",
    createParentPath: true,
    debug: process.env.NODE_ENV === "development",
  })
);
*/

// Configuração do method-override para permitir PUT e DELETE em formulários HTML
app.use(methodOverride("_method"));

// Configuração da sessão
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Definindo como false para permitir tanto HTTP quanto HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 horas
      sameSite: "lax", // Permite que o cookie seja enviado em redirecionamentos
    },
  })
);

// Inicializa o Passport para autenticação SAML
require("./config/passport")(app);

// Configura o simulador de IdP SAML (apenas em ambiente de desenvolvimento)
if (process.env.NODE_ENV !== "production") {
  try {
    const { setupIdpSimulator } = require("./config/saml-mock");
    setupIdpSimulator(app);
    console.log("Simulador de SAML IdP ativado para testes");
  } catch (error) {
    console.error("Erro ao configurar simulador de SAML:", error.message);
  }
}

// Configuração do flash
app.use(flash());

// Configuração das views
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(expressLayouts);
app.set("layout", "layouts/main");

// Middleware para passar variáveis globais para as views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.messages = {
    success: req.flash("success"),
    error: req.flash("error"),
    info: req.flash("info"),
  };

  // FORÇAR exibição do botão SSO independentemente das configurações
  // Ignorar verificação de samlConfig devido a problemas de cache
  console.log(
    "Forçando exibição do botão SSO independentemente da configuração"
  );
  res.locals.showSSOButton = true;

  // Adicionar timestamp para evitar problemas de cache
  res.locals.cacheVersion = Date.now();

  next();
});

// Middleware para transferir o token da sessão para o cabeçalho de autorização em requisições para a API
app.use((req, res, next) => {
  if (req.path.startsWith("/api/") && req.session && req.session.token) {
    req.headers.authorization = `Bearer ${req.session.token}`;
  }
  next();
});

// Configurações do servidor HTTP
const server = require("http").createServer(app);

// Configuração do Socket.io para comunicação em tempo real
const io = require("socket.io")(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// Middleware de autenticação para Socket.io
io.use(async (socket, next) => {
  try {
    const { playerId, playerKey, hardwareId } = socket.handshake.auth;

    // Verificar se as credenciais foram fornecidas
    if (!playerId || !playerKey) {
      return next(new Error("Credenciais inválidas"));
    }

    // Importar o modelo Player
    const Player = require("./models/player.model");

    // Verificar se o player existe e está autorizado
    const player = await Player.findById(playerId);
    if (!player) {
      return next(new Error("Player não encontrado"));
    }

    // Verificar a chave do player
    if (player.player_key !== playerKey) {
      return next(new Error("Chave de player inválida"));
    }

    // Verificar hardware ID se estiver configurado
    if (player.hardware_id && hardwareId && player.hardware_id !== hardwareId) {
      return next(new Error("Hardware ID não corresponde"));
    }

    // Adicionar player às informações do socket
    socket.playerData = {
      id: player._id,
      name: player.name,
      group: player.group,
    };

    // Atualizar status do player
    player.status = "online";
    player.last_connection = new Date();
    await player.save();

    console.log(
      `Player conectado via WebSocket: ${player.name} (${player._id})`
    );
    next();
  } catch (error) {
    return next(new Error("Erro de autenticação: " + error.message));
  }
});

// Configuração de eventos do Socket.io
io.on("connection", (socket) => {
  // Adicionar socket à sala específica do player
  const playerId = socket.playerData.id;
  socket.join(`player:${playerId}`);

  // Evento de ping do player
  socket.on("player-ping", async (data) => {
    try {
      // Importar o modelo Player
      const Player = require("./models/player.model");

      // Atualizar status do player no banco
      const player = await Player.findById(playerId);
      if (player) {
        player.status = "online";
        player.last_connection = new Date();
        if (data.current_media) {
          player.current_media = data.current_media;
        }
        await player.save();
      }
    } catch (error) {
      console.error("Erro ao processar ping do player:", error);
    }
  });

  // Evento de reprodução de mídia
  socket.on("media-playing", async (data) => {
    try {
      // Importar o modelo Player
      const Player = require("./models/player.model");

      // Atualizar mídia atual do player
      const player = await Player.findById(playerId);
      if (player) {
        player.current_media = data.media.name || data.media.id;
        await player.save();
      }

      // Emitir evento para administradores (opcional)
      io.to("admin").emit("player-media-update", {
        playerId,
        playerName: socket.playerData.name,
        media: data.media,
        timestamp: data.timestamp,
      });
    } catch (error) {
      console.error("Erro ao processar notificação de mídia:", error);
    }
  });

  // Evento de status do player
  socket.on("player-status", async (data) => {
    try {
      // Importar o modelo Player
      const Player = require("./models/player.model");

      // Atualizar status do player
      const player = await Player.findById(playerId);
      if (player) {
        player.status = data.status;
        player.last_connection = new Date();

        // Adicionar à lista de logs do player
        player.logs.push({
          timestamp: new Date(),
          level: data.status === "error" ? "error" : "info",
          message: data.message || `Status alterado para ${data.status}`,
        });

        // Limitar o número de logs
        if (player.logs.length > 100) {
          player.logs = player.logs.slice(-100);
        }

        await player.save();
      }

      // Emitir evento para administradores
      io.to("admin").emit("player-status-update", {
        playerId,
        playerName: socket.playerData.name,
        status: data.status,
        message: data.message,
        timestamp: data.timestamp,
      });
    } catch (error) {
      console.error("Erro ao processar alteração de status:", error);
    }
  });

  // Evento de desconexão
  socket.on("disconnect", async () => {
    try {
      // Importar o modelo Player
      const Player = require("./models/player.model");

      // Marcar player como offline no banco de dados
      const player = await Player.findById(playerId);
      if (player) {
        player.status = "offline";
        await player.save();
      }

      console.log(
        `Player desconectado: ${socket.playerData.name} (${playerId})`
      );
    } catch (error) {
      console.error("Erro ao processar desconexão do player:", error);
    }
  });
});

// Exportar Socket.io para uso em outros módulos
app.set("io", io);
// Disponibilizar io globalmente
global.io = io;

// Conexão com o MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Conectado ao MongoDB"))
  .catch((err) => console.error("Erro ao conectar ao MongoDB:", err));

// Importação das rotas
const authRoutes = require("./routes/auth.routes");
const userRoutes = require("./routes/user.routes");
const groupRoutes = require("./routes/group.routes");
const mediaRoutes = require("./routes/media.routes");
const playlistRoutes = require("./routes/playlist.routes");
const playerRoutes = require("./routes/player.routes");
const templateRoutes = require("./routes/template.routes");
const webRoutes = require("./routes/web.routes");
const apiRoutes = require("./routes/api.routes");
const rssRoutes = require("./routes/rss.routes");
const samlRoutes = require("./routes/saml.routes");

// Uso das rotas
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/groups", groupRoutes);
app.use("/api/media", mediaRoutes);
app.use("/api/playlists", playlistRoutes);
app.use("/api/players", playerRoutes);
app.use("/templates", templateRoutes);
app.use("/", webRoutes);
app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/groups", groupRoutes);
app.use("/media", mediaRoutes);
app.use("/players", playerRoutes);
app.use("/playlists", playlistRoutes);
app.use("/rss", rssRoutes);
app.use("/api", apiRoutes);

// Rotas SAML para autenticação SSO
app.use("/auth/saml", samlRoutes);

// Tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: "Erro interno do servidor",
    error: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// Exportar o servidor HTTP em vez de apenas o app
module.exports = { app, server };

// Iniciar verificação periódica do status dos players quando o MongoDB estiver conectado
mongoose.connection.once("open", () => {
  console.log("Conexão com MongoDB estabelecida");

  // Iniciar verificação periódica do status dos players (a cada 1 minuto)
  if (!checkPlayersStatusInterval) {
    checkPlayersStatusInterval = setInterval(checkPlayersStatus, 60000);
    console.log("Monitoramento automático de status dos players iniciado");
  }
});
