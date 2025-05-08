const jwt = require("jsonwebtoken");
const User = require("../models/user.model");

/**
 * Middleware de autenticação
 */
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Autenticação necessária",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).populate("group");

    if (!user || !user.active) {
      throw new Error();
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Token inválido ou expirado",
    });
  }
};

/**
 * Middleware para verificar se o usuário é admin
 */
const adminOnly = async (req, res, next) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message:
          "Acesso negado. Apenas administradores podem acessar este recurso.",
      });
    }

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao verificar permissões",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Middleware para verificar se o usuário pertence ao mesmo grupo ou admin
 */
const sameGroupOrAdmin = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Autenticação necessária",
      });
    }

    if (req.user.role === "admin") {
      return next();
    }

    const resourceGroup = req.body.group || req.params.group;
    if (!resourceGroup) {
      return next();
    }

    if (req.user.group._id.toString() !== resourceGroup.toString()) {
      return res.status(403).json({
        success: false,
        message: "Acesso negado. Você só pode acessar recursos do seu grupo.",
      });
    }

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao verificar permissões",
    });
  }
};

/**
 * Middleware para verificar se o usuário está autenticado nas rotas web
 */
const webAuth = async (req, res, next) => {
  try {
    console.log("========== DEBUG webAuth ==========");
    console.log("URL acessada:", req.originalUrl);
    console.log("Método HTTP:", req.method);
    console.log("Sessão existe:", !!req.session);
    console.log("Token na sessão:", !!req.session.token);
    console.log("Usuário na sessão:", !!req.session.user);

    if (req.session.user) {
      console.log("ID do usuário:", req.session.user._id);
      console.log("Email do usuário:", req.session.user.email);
      console.log("Papel do usuário:", req.session.user.role);
      console.log(
        "Grupo do usuário:",
        req.session.user.group
          ? req.session.user.group._id || req.session.user.group
          : "Nenhum"
      );

      // Define req.user para uso nas rotas
      req.user = req.session.user;

      // Garantir que o usuário tenha a propriedade groups
      if (!req.user.groups) {
        // Se o usuário tiver um grupo, crie um array com ele
        if (req.user.group) {
          const groupId = req.user.group._id || req.user.group;
          req.user.groups = [groupId.toString()];
          console.log("Grupos do usuário (criado):", req.user.groups);
        } else {
          // Se não tiver grupo, inicialize como array vazio
          req.user.groups = [];
          console.log("Grupos do usuário (vazio):", req.user.groups);
        }
      } else {
        console.log("Grupos do usuário (existente):", req.user.groups);
      }

      console.log("Autenticação bem-sucedida, prosseguindo para a rota");
      console.log("========== FIM DEBUG webAuth ==========");
      return next();
    }

    // Se não estiver na sessão, redireciona para a página de login
    console.log("Usuário não autenticado, redirecionando para login");
    console.log("========== FIM DEBUG webAuth ==========");
    return res.redirect("/auth/login");
  } catch (error) {
    console.error("Erro no middleware webAuth:", error);
    console.log("========== FIM DEBUG webAuth COM ERRO ==========");
    return res.redirect("/auth/login");
  }
};

/**
 * Middleware para verificar se o usuário é admin nas rotas web
 */
const webAdminOnly = (req, res, next) => {
  if (req.session.user && req.session.user.role === "admin") {
    return next();
  }
  return res.status(403).render("errors/403", {
    title: "Acesso Negado",
    message: "Você não tem permissão para acessar esta página.",
  });
};

/**
 * Middleware para verificar se o usuário pertence ao mesmo grupo ou é admin nas rotas web
 */
const webSameGroupOrAdmin = async (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/auth/login");
  }

  if (req.session.user.role === "admin") {
    return next();
  }

  // Verifica o ID do recurso
  const resourceId = req.params.id;
  if (!resourceId) {
    return next();
  }

  try {
    // Determinar qual modelo usar com base na URL
    let Model;
    if (req.originalUrl.includes("/media/")) {
      Model = require("../models/media.model");
    } else if (req.originalUrl.includes("/playlists/")) {
      Model = require("../models/playlist.model");
    } else if (req.originalUrl.includes("/players/")) {
      Model = require("../models/player.model");
    } else {
      // Se não conseguir determinar o modelo, permite o acesso
      return next();
    }

    // Busca o recurso no banco de dados
    const resource = await Model.findById(resourceId);

    if (!resource) {
      req.flash("error", "Recurso não encontrado");
      return res.redirect("back");
    }

    // Verifica se o grupo do recurso é o mesmo do usuário
    if (resource.group && req.session.user.group) {
      const userGroupId = req.session.user.group._id || req.session.user.group;
      if (resource.group.toString() !== userGroupId.toString()) {
        return res.status(403).render("errors/403", {
          title: "Acesso Negado",
          message: "Você não tem permissão para acessar este recurso.",
        });
      }
    }

    next();
  } catch (error) {
    console.error("Erro ao verificar permissões de grupo:", error);
    req.flash("error", "Erro ao verificar permissões");
    return res.redirect("back");
  }
};

module.exports = {
  auth,
  adminOnly,
  sameGroupOrAdmin,
  webAuth,
  webAdminOnly,
  webSameGroupOrAdmin,
};
