const User = require("../models/user.model");
const jwt = require("jsonwebtoken");

/**
 * Registra um novo usuário (apenas admin pode fazer isso)
 */
const register = async (req, res) => {
  try {
    const { name, email, password, role, group } = req.body;

    // Verifica se o email já está em uso
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email já está em uso",
      });
    }

    // Cria o novo usuário
    const user = new User({
      name,
      email,
      password,
      role: role || "user",
      group,
    });

    await user.save();

    res.status(201).json({
      success: true,
      message: "Usuário criado com sucesso",
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao registrar usuário",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Autentica um usuário e retorna um token JWT
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Busca o usuário pelo email
    const user = await User.findOne({ email, active: true });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Credenciais inválidas",
      });
    }

    // Verifica a senha
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Credenciais inválidas",
      });
    }

    // Atualiza o último login
    user.lastLogin = new Date();
    await user.save();

    // Gera o token JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.status(200).json({
      success: true,
      message: "Login realizado com sucesso",
      data: {
        user,
        token,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao fazer login",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Retorna o perfil do usuário autenticado
 */
const getProfile = async (req, res) => {
  try {
    // O usuário já está disponível em req.user graças ao middleware de autenticação
    const user = await User.findById(req.user._id).populate("group");

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao buscar perfil",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Altera a senha do usuário autenticado
 */
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Verifica a senha atual
    const isMatch = await req.user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Senha atual incorreta",
      });
    }

    // Atualiza a senha
    req.user.password = newPassword;
    await req.user.save();

    res.status(200).json({
      success: true,
      message: "Senha alterada com sucesso",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao alterar senha",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

/**
 * Processa o login e armazena o usuário na sessão
 */
const processLogin = async (req, res) => {
  try {
    const { token, user } = req.body;

    // Buscar o usuário completo com o grupo populado
    const completeUser = await User.findById(user._id).populate("group");

    // Armazena o usuário completo e o token na sessão
    req.session.user = completeUser || user;
    req.session.token = token;

    // Redireciona para o dashboard
    res.status(200).json({
      success: true,
      message: "Login processado com sucesso",
      redirectTo: "/dashboard",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Erro ao processar login",
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

module.exports = {
  register,
  login,
  getProfile,
  changePassword,
  processLogin,
};
