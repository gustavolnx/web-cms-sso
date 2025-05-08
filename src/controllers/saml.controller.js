const passport = require("passport");
const User = require("../models/user.model");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const Group = require("../models/group.model");
const axios = require("axios");

// Carrega as variáveis de ambiente
dotenv.config();

/**
 * Inicia o processo de login SAML
 */
const initiateLogin = (req, res, next) => {
  // Sempre exibir informações de debug para identificar problemas
  console.log("Iniciando autenticação SAML...");
  try {
    console.log("Redirecionando para provedor de identidade...");
    passport.authenticate("saml", {
      successRedirect: "/dashboard",
      failureRedirect: "/auth/login",
      failureFlash: true,
    })(req, res, next);
  } catch (error) {
    console.error("Erro ao iniciar autenticação SAML:", error);
    req.flash("error", "Erro ao iniciar autenticação SAML");
    res.redirect("/auth/login");
  }
};

/**
 * Processa o retorno da autenticação SAML (callback)
 */
const handleCallback = (req, res, next) => {
  console.log("========== DEBUG SAML Callback ==========");
  console.log("Recebida resposta SAML");
  console.log("Método:", req.method);
  console.log("URL:", req.originalUrl);
  console.log("Tem SAMLResponse:", !!req.body.SAMLResponse);

  // Verifica se é uma resposta do simulador local de IdP
  if (req.body.SAMLResponse && req.body.SAMLResponse.startsWith("eyJ")) {
    try {
      console.log("Detectada resposta do simulador local");
      // Decodifica a resposta simulada (base64)
      const simulatedData = JSON.parse(atob(req.body.SAMLResponse));

      // Cria um perfil com os dados simulados
      const profile = {
        nameID: simulatedData.nameId,
        email: simulatedData.email,
        displayName: simulatedData.nome,
        group: simulatedData.grupo,
      };

      console.log("Dados do simulador de IdP:", profile);

      // Continua o fluxo com os dados simulados
      processUserProfile(req, res, null, profile);
      return;
    } catch (error) {
      console.error("Erro ao processar dados do simulador de IdP:", error);
      req.flash("error", "Erro ao processar dados do simulador");
      console.log(
        "========== FIM DEBUG SAML Callback (erro simulador) =========="
      );
      return res.redirect("/auth/login");
    }
  }

  console.log("Processando resposta SAML padrão");
  // Caso não seja do simulador, continua com o processamento normal SAML
  passport.authenticate("saml", async (err, profile, info) => {
    console.log("Callback do passport.authenticate SAML");
    console.log("Erro:", err ? "Sim" : "Não");
    console.log("Perfil:", profile ? "Recebido" : "Não recebido");

    try {
      processUserProfile(req, res, err, profile, info);
    } catch (error) {
      console.error("Erro no processamento da autenticação:", error);
      req.flash("error", "Erro interno durante autenticação");
      console.log(
        "========== FIM DEBUG SAML Callback (erro autenticação) =========="
      );
      return res.redirect("/auth/login");
    }
  })(req, res, next);
};

/**
 * Função auxiliar para processar o perfil do usuário e fazer login
 */
const processUserProfile = async (req, res, err, profile, info) => {
  console.log("========== DEBUG processUserProfile ==========");
  try {
    if (err) {
      console.error("Erro na autenticação SAML:", err);
      req.flash("error", "Erro na autenticação SAML");
      console.log(
        "========== FIM DEBUG processUserProfile (erro SAML) =========="
      );
      return res.redirect("/auth/login");
    }

    if (!profile) {
      console.error("Perfil SAML não encontrado:", info);
      req.flash("error", "Não foi possível autenticar via SSO");
      console.log(
        "========== FIM DEBUG processUserProfile (sem perfil) =========="
      );
      return res.redirect("/auth/login");
    }

    // Extrai os dados do perfil SAML
    const email = profile.email || profile.nameID;
    const name = profile.displayName || profile.nameID;
    console.log("Email extraído:", email);
    console.log("Nome extraído:", name);

    // Busca o usuário ou cria um novo se não existir
    let user = await User.findOne({ email }).populate("group");
    console.log("Usuário encontrado no banco:", user ? "Sim" : "Não");

    if (!user) {
      console.log("Criando novo usuário para login SAML");
      // Procura um grupo padrão para usuários via SSO
      let defaultGroup;

      // Se o perfil tiver um grupo especificado, tenta encontrá-lo primeiro
      if (profile.group) {
        console.log("Buscando grupo do perfil:", profile.group);
        defaultGroup = await Group.findOne({ name: profile.group });
      }

      // Se não tiver grupo no perfil ou não encontrou o grupo, busca pelo grupo "Administração" que é criado pelo init-db.js
      if (!defaultGroup) {
        console.log("Buscando grupo padrão 'Administração'");
        defaultGroup = await Group.findOne({ name: "Administração" });
      }

      // Se ainda não encontrou nenhum grupo, busca qualquer grupo ativo
      if (!defaultGroup) {
        console.log("Buscando qualquer grupo ativo");
        defaultGroup = await Group.findOne({ active: true });
      }

      // Se não encontrou nenhum grupo, registra erro e redireciona
      if (!defaultGroup) {
        console.error(
          "Não foi possível encontrar um grupo para associar ao usuário SSO"
        );
        req.flash(
          "error",
          "Erro interno: não foi possível associar grupo ao usuário"
        );
        console.log(
          "========== FIM DEBUG processUserProfile (sem grupo) =========="
        );
        return res.redirect("/auth/login");
      }

      console.log("Grupo encontrado:", defaultGroup.name);

      // Cria um novo usuário automaticamente com o grupo padrão
      user = new User({
        name: name,
        email: email,
        password: Math.random().toString(36).slice(-10), // Senha aleatória
        role: "user", // Define o papel padrão
        group: defaultGroup._id,
        active: true,
      });

      // Atualiza o papel do usuário se o grupo tiver papel padrão
      if (defaultGroup.defaultRole) {
        user.role = defaultGroup.defaultRole;
        console.log("Papel do usuário definido para:", user.role);
      }

      await user.save();
      console.log(
        `Novo usuário ${email} criado via SSO e associado ao grupo ${defaultGroup.name}`
      );
    }

    // Verifica se o usuário está ativo
    if (!user.active) {
      console.log("Usuário desativado, bloqueando acesso");
      req.flash(
        "error",
        "Usuário desativado, entre em contato com o administrador"
      );
      console.log(
        "========== FIM DEBUG processUserProfile (usuário inativo) =========="
      );
      return res.redirect("/auth/login");
    }

    console.log("Gerando token JWT para o usuário");
    // Gera o token JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log("Buscando usuário completo com grupo populado");
    // Em vez de chamar diretamente a função processLogin, vamos fazer o que ela faria
    // mas adequado para o fluxo SAML com redirecionamento

    // Buscar o usuário completo com o grupo populado
    const completeUser = await User.findById(user._id).populate("group");
    console.log("Usuário completo encontrado:", !!completeUser);

    console.log("Armazenando usuário e token na sessão");
    // Armazena o usuário completo e o token na sessão
    req.session.user = completeUser || user;
    req.session.token = token;

    console.log("Sessão após atribuição:");
    console.log("- user._id:", req.session.user._id);
    console.log("- user.email:", req.session.user.email);
    console.log("- user.role:", req.session.user.role);
    console.log(
      "- user.group:",
      req.session.user.group
        ? req.session.user.group._id || req.session.user.group
        : "Nenhum"
    );
    console.log("- token existe:", !!req.session.token);

    // Atualiza o último login
    user.lastLogin = new Date();
    await user.save();
    console.log("Último login atualizado");

    // Registra a autenticação no log
    console.log(`Usuário ${user.email} autenticado via SAML`);

    // Salva a sessão explicitamente antes de redirecionar
    req.session.save((err) => {
      if (err) {
        console.error("Erro ao salvar sessão:", err);
        req.flash("error", "Erro ao finalizar login");
        console.log(
          "========== FIM DEBUG processUserProfile (erro ao salvar sessão) =========="
        );
        return res.redirect("/auth/login");
      }

      console.log("Sessão salva com sucesso");
      console.log("Redirecionando para /dashboard");
      console.log(
        "========== FIM DEBUG processUserProfile (sucesso) =========="
      );

      // Redireciona para o dashboard
      return res.redirect("/dashboard");
    });
  } catch (error) {
    console.error("Erro ao processar perfil do usuário:", error);
    req.flash("error", "Erro ao processar perfil do usuário");
    console.log("========== FIM DEBUG processUserProfile (erro) ==========");
    return res.redirect("/auth/login");
  }
};

/**
 * Processa o logout SAML
 */
const logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Erro ao encerrar sessão:", err);
    }
    res.redirect("/auth/login");
  });
};

/**
 * Rota para gerar os metadados SAML
 */
const getMetadata = (req, res) => {
  const samlStrategy = req._passport.instance._strategies.saml;

  try {
    const metadata = samlStrategy.generateServiceProviderMetadata();
    res.header("Content-Type", "text/xml").send(metadata);
  } catch (error) {
    console.error("Erro ao gerar metadados SAML:", error);
    res.status(500).send("Erro ao gerar metadados SAML");
  }
};

/**
 * Gera um arquivo de configuração SAML para download
 */
const downloadConfig = (req, res) => {
  try {
    const samlConfig = require("../config/saml.config");
    const appUrl = process.env.APP_URL || "https://cms.suaempresa.com.br";

    // Criar objeto de configuração para download
    const config = {
      service_provider: {
        entity_id: samlConfig.issuer,
        assertion_consumer_service: {
          url: samlConfig.callbackUrl,
          binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        metadata_url: `${appUrl}/auth/saml/metadata`,
        name_id_format: samlConfig.identifierFormat,
      },
      instructions: {
        pt: [
          "Configure um novo aplicativo SAML no seu provedor de identidade",
          "Defina o Entity ID (Identificador) como: " + samlConfig.issuer,
          "Defina o Reply URL (URL de Resposta) como: " +
            samlConfig.callbackUrl,
          "Use o URL de metadados para configuração automática: " +
            `${appUrl}/auth/saml/metadata`,
          "Envie o URL de Login (Entry Point) e certificado X.509 do seu provedor para nossa equipe",
        ],
        en: [
          "Set up a new SAML application in your identity provider",
          "Set the Entity ID as: " + samlConfig.issuer,
          "Set the Reply URL (Assertion Consumer Service URL) as: " +
            samlConfig.callbackUrl,
          "Use the metadata URL for automatic configuration: " +
            `${appUrl}/auth/saml/metadata`,
          "Send us the Login URL (Entry Point) and X.509 certificate from your provider",
        ],
      },
    };

    // Configurar cabeçalhos para download
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=saml-config.json"
    );
    res.setHeader("Content-Type", "application/json");

    // Enviar o arquivo
    res.json(config);
  } catch (error) {
    console.error("Erro ao gerar arquivo de configuração SAML:", error);
    req.flash("error", "Erro ao gerar arquivo de configuração SAML");
    res.redirect("/admin/saml-info");
  }
};

module.exports = {
  initiateLogin,
  handleCallback,
  logout,
  getMetadata,
  downloadConfig,
};
