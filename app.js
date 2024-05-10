// ******************************************************************************************
// *************************************  DEPENDENCIAS  *************************************
// ******************************************************************************************
require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const cors = require('cors');
const http = require('http');
const { Sequelize } = require('sequelize');
const socketIo = require('socket.io');

// Modelos
const User = require("./User.js");
const Notification = require('./notifications.js'); // Ajuste o caminho conforme necessário
const ResetToken = require('./ResetToken.js'); // Ajuste o caminho conforme necessário
const sequelize = require('./database'); // Certifique-se que o caminho está correto

ResetToken.belongsTo(User, { foreignKey: 'userId', as: 'user' });
User.hasMany(ResetToken, { foreignKey: 'userId' });

// Configuração do Express
const app = express();
app.use(express.json());
app.use(cors());

// Configuração do servidor HTTP e Socket.IO
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://trucoarena.online",  // Atualize para permitir seu domínio
    methods: ["GET", "POST"]
  }
});

// Verificar conexão com o banco
async function checkDatabaseConnection() {
    try {
        await sequelize.authenticate();
        console.log('💤 Conectou ao banco MySQL com sucesso!');
    } catch (error) {
        console.error('Erro ao conectar ao banco de dados MySQL:', error);
    }
}

checkDatabaseConnection();

// ******************************************************************************************
// *************************************  ROTA ABERTA  **************************************
// ******************************************************************************************
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo à API TRUCO ARENA!" });
});

// Inicialização do servidor depois de verificar a conexão com o banco de dados
server.listen(3000, () => {
    console.log(`Servidor rodando na porta 3000`);
});

// ******************************************************************************************
// **********************************  ROTA PRIVADA USUÁRIO  *******************************
// ******************************************************************************************
app.get("/user/:id", checkToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Use Sequelize's `findByPk` method and exclude the password field
    const user = await User.findByPk(id, {
      attributes: { exclude: ['password'] } // Exclude password from the results
    });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({ user });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ msg: "Erro ao buscar usuário" });
  }
});

// Middleware para verificar token
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ msg: "Acesso negado!" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ msg: "O Token é inválido!" });
  }
}

// ******************************************************************************************
// *********************************  ROTA DE REGISTRO  *************************************
// ******************************************************************************************
// ROTA DE REGISTRO COM VERIFICAÇÃO DE E-MAIL
// ROTA DE REGISTRO COM VERIFICAÇÃO DE E-MAIL
app.post("/auth/register", async (req, res) => {
  const { name, email, password, username } = req.body;
  if (!name || !email || !password || !username) {
    return res.status(400).json({ msg: "Todos os campos são obrigatórios: nome, email, senha e nome de usuário." });
  }

  try {
    const userExists = await User.findOne({ where: { email } });
    if (userExists) {
      return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" });
    }

    const usernameExists = await User.findOne({ where: { username } });
    if (usernameExists) {
      return res.status(422).json({ msg: "O nome de usuário já está em uso!" });
    }

    const token = crypto.randomInt(100000, 1000000).toString();

    // Aqui, em vez de criar imediatamente o usuário, salvamos o token de verificação
    // Você pode ajustar isso para salvar em uma tabela separada se preferir
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Salvar o usuário como inativo ou não confirmado dependendo de sua lógica de negócio
    const user = await User.create({
      name,
      email,
      password: passwordHash,
      username,
      verificationToken: token, // Adicione uma coluna na sua tabela de usuários para isso
      isActive: false // Supondo que você tenha uma coluna para verificar se o usuário está ativo
    });

    sendVerificationEmail(email, token);

    res.status(201).json({ msg: "Um e-mail com o token de verificação foi enviado. Verifique seu e-mail para ativar sua conta." });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// ROTA PARA VERIFICAR O TOKEN DE E-MAIL
app.post("/auth/verify-email", async (req, res) => {
  const { email, token } = req.body;

  try {
    const user = await User.findOne({ where: { email, verificationToken: token } });

    if (!user) {
      return res.status(400).json({ msg: "Token inválido ou e-mail incorreto!" });
    }

    user.isActive = true;
    user.verificationToken = null; // Limpar o token depois da verificação
    await user.save();

    res.status(200).json({ msg: "Conta ativada com sucesso!" });
  } catch (error) {
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

// ROTA PARA REENVIAR O TOKEN DE VERIFICAÇÃO DE E-MAIL
app.post("/auth/resend-verification", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ msg: "E-mail é obrigatório!" });
  }

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    // Usuário encontrado mas já está ativo
    if (user.isActive) {
      return res.status(400).json({ msg: "Este e-mail já foi verificado." });
    }

    // Gerar um novo token de verificação
    const newToken = crypto.randomInt(100000, 1000000).toString();

    // Atualizar o token na base de dados
    user.verificationToken = newToken;
    await user.save();

    // Reenviar o e-mail com o novo token
    sendVerificationEmail(email, newToken);

    res.status(200).json({ msg: "Um novo e-mail de verificação foi enviado." });
  } catch (error) {
    res.status(500).json({ msg: "Erro interno do servidor", error: error.message });
  }
});


// Função para enviar e-mail de verificação
async function sendVerificationEmail(to, token) {
  let transporter = nodemailer.createTransport({
      host: 'smtp.hostinger.com',
      port: 465,
      secure: true,
      auth: {
          user: 'suporte@trucoarena.com',
          pass: 'Truco*Server10'
      }
  });

  const formattedToken = token.split('').join(' ');

  let info = await transporter.sendMail({
      from: '"Truco Arena" <suporte@trucoarena.com>',
      to: to,
      subject: "Verificação de E-mail",
      html: `
      <!DOCTYPE html><html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" lang="pt-BR"><head><title></title><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch><o:AllowPNG/></o:OfficeDocumentSettings></xml><![endif]--><!--[if !mso]><!--><link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@100;200;300;400;500;600;700;800;900" rel="stylesheet" type="text/css"><!--<![endif]--><style> *{box-sizing:border-box}body{margin:0;padding:0}a[x-apple-data-detectors]{color:inherit !important;text-decoration:inherit !important}#MessageViewBody a{color:inherit;text-decoration:none}p{line-height:inherit}.desktop_hide,.desktop_hide table{mso-hide:all;display:none;max-height:0px;overflow:hidden}.image_block img+div{display:none}@media (max-width:620px){.mobile_hide{display:none}.row-content{width:100% !important}.stack .column{width:100%;display:block}.mobile_hide{min-height:0;max-height:0;max-width:0;overflow:hidden;font-size:0px}.desktop_hide,.desktop_hide table{display:table !important;max-height:none !important}.row-1 .column-1 .block-7.paragraph_block td.pad>div{font-size:13px !important}}</style></head><body style="margin: 0; background-color: #091548; padding: 0; -webkit-text-size-adjust: none; text-size-adjust: none;"><table class="nl-container" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #091548;"><tbody><tr><td><table class="row row-1" align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #091548; background-image: url('https://d1oco4z2z1fhwp.cloudfront.net/templates/default/3986/background_2.png'); background-position: center top; background-repeat: repeat;"><tbody><tr><td><table class="row-content stack" align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; color: #000000; width: 600px; margin: 0 auto;" width="600"><tbody><tr><td class="column column-1" width="100%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 15px; padding-left: 10px; padding-right: 10px; padding-top: 5px; vertical-align: top; border-top: 0px; border-right: 0px; border-bottom: 0px; border-left: 0px;"><div class="spacer_block block-1" style="height:8px;line-height:8px;font-size:1px;">&#8202;</div><table class="image_block block-2" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad" style="width:100%;padding-right:0px;padding-left:0px;"><div class="alignment" align="center" style="line-height:10px"><div style="max-width: 232px;"><img src="https://d1oco4z2z1fhwp.cloudfront.net/templates/default/3986/header3.png" style="display: block; height: auto; border: 0; width: 100%;" width="232" alt="Main Image" title="Main Image" height="auto"></div></div></td></tr></table><table class="paragraph_block block-3" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad" style="padding-bottom:15px;padding-top:10px;"><div style="color:#ffffff;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:30px;line-height:120%;text-align:center;mso-line-height-alt:36px;"><p style="margin: 0; word-break: break-word;"><span>Verificar conta</span></p></div></td></tr></table><table class="paragraph_block block-4" width="100%" border="0" cellpadding="5" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad"><div style="color:#ffffff;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:14px;line-height:150%;text-align:center;mso-line-height-alt:21px;"><p style="margin: 0; word-break: break-word;">Bem vindo, aqui está seu código de verificação.<br>Estamos aqui para ajudá-lo. Seu código é:</p></div></td></tr></table><table class="html_block block-5" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad"><div style="font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;text-align:center;" align="center"><div><a href="www.trucoarena.com" target="_blank" style="text-decoration:none;display:inline-block;color:#091548;background-color:#ffffff;margin:10px;border-radius:5px;padding:5px;padding-top:10px;padding-bottom:10px;width:auto;font-weight:400;padding-top:5px;padding-bottom:5px;font-family:'Montserrat', 'Trebuchet MS', 'Lucida Grande', 'Lucida Sans Unicode', 'Lucida Sans', Tahoma, sans-serif;font-size:18px;text-align:center;letter-spacing:6px;"><strong>${formattedToken}</strong></a></div></div></td></tr></table><table class="divider_block block-6" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad" style="padding-bottom:15px;padding-left:10px;padding-right:10px;padding-top:10px;"><div class="alignment" align="center"><table border="0" cellpadding="0" cellspacing="0" role="presentation" width="60%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="divider_inner" style="font-size: 1px; line-height: 1px; border-top: 1px solid #5A6BA8;"><span>&#8202;</span></td></tr></table></div></td></tr></table><table class="paragraph_block block-7" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad" style="padding-bottom:10px;padding-left:25px;padding-right:25px;padding-top:10px;"><div style="color:#7f96ef;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:14px;line-height:150%;text-align:center;mso-line-height-alt:21px;"><p style="margin: 0; word-break: break-word;">Não criou uma conta?<br>Você pode ignorar esta mensagem.</p></div></td></tr></table><div class="spacer_block block-8" style="height:30px;line-height:30px;font-size:1px;">&#8202;</div></td></tr></tbody></table></td></tr></tbody></table><table class="row row-2" align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tbody><tr><td><table class="row-content stack" align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; color: #000000; width: 600px; margin: 0 auto;" width="600"><tbody><tr><td class="column column-1" width="100%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 15px; padding-left: 10px; padding-right: 10px; padding-top: 15px; vertical-align: top; border-top: 0px; border-right: 0px; border-bottom: 0px; border-left: 0px;"><table class="image_block block-1" width="100%" border="0" cellpadding="5" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad"><div class="alignment" align="center" style="line-height:10px"><div style="max-width: 174px;"><img src="https://d15k2d11r6t6rl.cloudfront.net/pub/bfra/v9y5vrmn/2rv/iqd/bri/logo-truco-arena-semfundo.png" style="display: block; height: auto; border: 0; width: 100%;" width="174" alt="Truco Arena" title="Truco Arena" height="auto"></div></div></td></tr></table><table class="divider_block block-2" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad" style="padding-bottom:15px;padding-left:10px;padding-right:10px;padding-top:15px;"><div class="alignment" align="center"><table border="0" cellpadding="0" cellspacing="0" role="presentation" width="60%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="divider_inner" style="font-size: 1px; line-height: 1px; border-top: 1px solid #5A6BA8;"><span>&#8202;</span></td></tr></table></div></td></tr></table><table class="paragraph_block block-3" width="100%" border="0" cellpadding="15" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad"><div style="color:#4a60bb;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:12px;line-height:120%;text-align:center;mso-line-height-alt:14.399999999999999px;"><p style="margin: 0; word-break: break-word;">Copyright © 2024 Truco Arena, Todos os direitos reservados.</p><p style="margin: 0; word-break: break-word;"><br>Deseja enviar um e-mail?</p><p style="margin: 0; word-break: break-word;">suporte@trucoarena.com</p></div></td></tr></table><table class="html_block block-4" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad"><div style="font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;text-align:center;" align="center"><div style="height-top: 20px;">&nbsp;</div></div></td></tr></table></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table></body></html>
      `
  });
}

// ******************************************************************************************
// *********************************  ROTAS DE NOTIFICAÇÕES  ********************************
// ******************************************************************************************
app.post("/notifications/create", async (req, res) => {
  const { title, description, type } = req.body;
  let { user } = req.body;

  // Verifica se os campos necessários estão presentes
  if (!title || !description || !type) {
    return res.status(400).json({ msg: "Todos os campos são obrigatórios: title, description, type." });
  }

  // Se o campo user for 'global', ajusta para a palavra reservada 'global'
  if (user === 'global') {
    user = 'global';
  } else {
    // Verifica se o usuário existe antes de criar a notificação
    const userExists = await User.findByPk(user);
    if (!userExists) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }
  }

  // Define a data de expiração para 2 dias após a criação
  const dateCreated = new Date();
  const expiredDate = new Date(dateCreated);
  expiredDate.setDate(expiredDate.getDate() + 2); // Adiciona 2 dias à data de criação

  // Cria a notificação
  try {
    const notification = await Notification.create({
      title,
      description,
      dateCreated: dateCreated,
      expiredDate: expiredDate,
      user,
      type
    });
    res.status(201).json({ msg: "Notificação criada com sucesso!", notification });
  } catch (error) {
    console.error('Erro ao criar notificação:', error);
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

app.delete("/notifications/delete/:id", async (req, res) => {
  const { id } = req.params;

  try {
      // Verifica se a notificação existe antes de tentar deletá-la
      const notification = await Notification.findByPk(id);
      if (!notification) {
          return res.status(404).json({ msg: "Notificação não encontrada!" });
      }

      // Deleta a notificação
      await Notification.destroy({
          where: { id }
      });

      res.status(200).json({ msg: "Notificação deletada com sucesso!" });
  } catch (error) {
      console.error('Erro ao deletar notificação:', error);
      res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

app.get("/notifications/update/:id", async (req, res) => {
  const { id } = req.params;  // Extrai o ID do usuário dos parâmetros da rota

  try {
      // Busca todas as notificações associadas a esse ID de usuário
      const notifications = await Notification.findAll({
          where: { user: id }
      });

      // Verifica se foram encontradas notificações
      if (!notifications || notifications.length === 0) {
          return res.status(404).json({ msg: "Nenhuma notificação encontrada para este usuário." });
      }

      // Retorna as notificações encontradas em formato JSON
      res.status(200).json(notifications);
  } catch (error) {
      console.error('Erro ao buscar notificações:', error);
      res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

// ******************************************************************************************
// *********************************  ROTA DE LOGIN  ****************************************
// ******************************************************************************************
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
      return res.status(422).json({ msg: "Senha inválida" });
    }

    const secret = process.env.JWT_SECRET;
    const token = jwt.sign({ id: user.id }, secret, { expiresIn: '1h' });
    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    res.status(500).json({ msg: error });
  }
});

app.get("/user/data/:email", async (req, res) => {
  const { email } = req.params;

  try {
    // Retrieve user data by email, selecting specific attributes
    const user = await User.findOne({
      where: { email },
      attributes: ['points', 'id', 'username', 'email'] // Ensures only these fields are retrieved
    });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({
      points: user.points,
      objectId: user.id,
      username: user.username,
      email: user.email
    });
  } catch (error) {
    console.error('Erro ao buscar os dados do usuário:', error);
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

// ******************************************************************************************
// *********************************  ROTA DE REQUEST-RESET  *******************************
// ******************************************************************************************
app.post("/auth/request-reset", async (req, res) => {
  const { email } = req.body;

  try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
          return res.status(404).json({ msg: "Usuário não encontrado com este e-mail!" });
      }

      const token = crypto.randomInt(100000, 1000000).toString();
      const expireAt = new Date();
      expireAt.setMinutes(expireAt.getMinutes() + 10);

      await ResetToken.create({
          userId: user.id, // Referencing the primary key automatically
          token: token,
          expireAt: expireAt
      });

      sendResetEmail(user.email, token);
      res.json({ msg: "Um e-mail com o token de reset foi enviado." });
  } catch (error) {
      console.error('Error on reset request:', error);
      res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

async function sendResetEmail(to, token) {
  let transporter = nodemailer.createTransport({
      host: 'smtp.hostinger.com',
      port: 465,
      secure: true,
      auth: {
          user: 'suporte@trucoarena.com',
          pass: 'Truco*Server10'
      }
  });

  const formattedToken = token.split('').join(' ');

  // Place to insert the HTML email content
  const htmlContent = `
  <!DOCTYPE html><html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" lang="pt-BR"><head><title></title><meta http-equiv="Content-Type" content="text/html; charset=utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch><o:AllowPNG/></o:OfficeDocumentSettings></xml><![endif]--><!--[if !mso]><!--><link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@100;200;300;400;500;600;700;800;900" rel="stylesheet" type="text/css"><!--<![endif]--><style> *{box-sizing:border-box}body{margin:0;padding:0}a[x-apple-data-detectors]{color:inherit !important;text-decoration:inherit !important}#MessageViewBody a{color:inherit;text-decoration:none}p{line-height:inherit}.desktop_hide,.desktop_hide table{mso-hide:all;display:none;max-height:0px;overflow:hidden}.image_block img+div{display:none}@media (max-width:620px){.mobile_hide{display:none}.row-content{width:100% !important}.stack .column{width:100%;display:block}.mobile_hide{min-height:0;max-height:0;max-width:0;overflow:hidden;font-size:0px}.desktop_hide,.desktop_hide table{display:table !important;max-height:none !important}.row-1 .column-1 .block-7.paragraph_block td.pad>div{font-size:13px !important}}</style></head><body style="margin: 0; background-color: #091548; padding: 0; -webkit-text-size-adjust: none; text-size-adjust: none;"><table class="nl-container" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #091548;"><tbody><tr><td><table class="row row-1" align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: #091548; background-image: url('https://d1oco4z2z1fhwp.cloudfront.net/templates/default/3986/background_2.png'); background-position: center top; background-repeat: repeat;"><tbody><tr><td><table class="row-content stack" align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; color: #000000; width: 600px; margin: 0 auto;" width="600"><tbody><tr><td class="column column-1" width="100%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 15px; padding-left: 10px; padding-right: 10px; padding-top: 5px; vertical-align: top; border-top: 0px; border-right: 0px; border-bottom: 0px; border-left: 0px;"><div class="spacer_block block-1" style="height:8px;line-height:8px;font-size:1px;">&#8202;</div><table class="image_block block-2" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad" style="width:100%;padding-right:0px;padding-left:0px;"><div class="alignment" align="center" style="line-height:10px"><div style="max-width: 232px;"><img src="https://d1oco4z2z1fhwp.cloudfront.net/templates/default/3986/header3.png" style="display: block; height: auto; border: 0; width: 100%;" width="232" alt="Main Image" title="Main Image" height="auto"></div></div></td></tr></table><table class="paragraph_block block-3" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad" style="padding-bottom:15px;padding-top:10px;"><div style="color:#ffffff;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:30px;line-height:120%;text-align:center;mso-line-height-alt:36px;"><p style="margin: 0; word-break: break-word;"><span>Resetar sua senha</span></p></div></td></tr></table><table class="paragraph_block block-4" width="100%" border="0" cellpadding="5" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad"><div style="color:#ffffff;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:14px;line-height:150%;text-align:center;mso-line-height-alt:21px;"><p style="margin: 0; word-break: break-word;">Recebemos uma solicitação para redefinir sua senha. Não se preocupe,<br>Estamos aqui para ajudá-lo. Seu código é:</p></div></td></tr></table><table class="html_block block-5" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad"><div style="font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;text-align:center;" align="center"><div><a href="www.trucoarena.com" target="_blank" style="text-decoration:none;display:inline-block;color:#091548;background-color:#ffffff;margin:10px;border-radius:5px;padding:5px;padding-top:10px;padding-bottom:10px;width:auto;font-weight:400;padding-top:5px;padding-bottom:5px;font-family:'Montserrat', 'Trebuchet MS', 'Lucida Grande', 'Lucida Sans Unicode', 'Lucida Sans', Tahoma, sans-serif;font-size:18px;text-align:center;letter-spacing:6px;"><strong>${formattedToken}</strong></a></div></div></td></tr></table><table class="divider_block block-6" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad" style="padding-bottom:15px;padding-left:10px;padding-right:10px;padding-top:10px;"><div class="alignment" align="center"><table border="0" cellpadding="0" cellspacing="0" role="presentation" width="60%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="divider_inner" style="font-size: 1px; line-height: 1px; border-top: 1px solid #5A6BA8;"><span>&#8202;</span></td></tr></table></div></td></tr></table><table class="paragraph_block block-7" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad" style="padding-bottom:10px;padding-left:25px;padding-right:25px;padding-top:10px;"><div style="color:#7f96ef;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:14px;line-height:150%;text-align:center;mso-line-height-alt:21px;"><p style="margin: 0; word-break: break-word;">Não solicitou uma redefinição de senha?<br>Você pode ignorar esta mensagem.</p></div></td></tr></table><div class="spacer_block block-8" style="height:30px;line-height:30px;font-size:1px;">&#8202;</div></td></tr></tbody></table></td></tr></tbody></table><table class="row row-2" align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tbody><tr><td><table class="row-content stack" align="center" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; color: #000000; width: 600px; margin: 0 auto;" width="600"><tbody><tr><td class="column column-1" width="100%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; font-weight: 400; text-align: left; padding-bottom: 15px; padding-left: 10px; padding-right: 10px; padding-top: 15px; vertical-align: top; border-top: 0px; border-right: 0px; border-bottom: 0px; border-left: 0px;"><table class="image_block block-1" width="100%" border="0" cellpadding="5" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad"><div class="alignment" align="center" style="line-height:10px"><div style="max-width: 174px;"><img src="https://cdn.discordapp.com/attachments/1211015987273670747/1234514900177387591/logo-truco-arena-semfundo.png?ex=66310318&is=662fb198&hm=61a27d02fc7c6e1c1f7e3697a16b416b887a55546b4098d8512d1acd10117fe2&" style="display: block; height: auto; border: 0; width: 100%;" width="174" alt="Truco Arena" title="Truco Arena" height="auto"></div></div></td></tr></table><table class="divider_block block-2" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad" style="padding-bottom:15px;padding-left:10px;padding-right:10px;padding-top:15px;"><div class="alignment" align="center"><table border="0" cellpadding="0" cellspacing="0" role="presentation" width="60%" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="divider_inner" style="font-size: 1px; line-height: 1px; border-top: 1px solid #5A6BA8;"><span>&#8202;</span></td></tr></table></div></td></tr></table><table class="paragraph_block block-3" width="100%" border="0" cellpadding="15" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt; word-break: break-word;"><tr><td class="pad"><div style="color:#4a60bb;font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;font-size:12px;line-height:120%;text-align:center;mso-line-height-alt:14.399999999999999px;"><p style="margin: 0; word-break: break-word;">Copyright © 2024 Truco Arena, Todos os direitos reservados.</p><p style="margin: 0; word-break: break-word;"><br>Deseja enviar um e-mail?</p><p style="margin: 0; word-break: break-word;">suporte@trucoarena.com</p></div></td></tr></table><table class="html_block block-4" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="mso-table-lspace: 0pt; mso-table-rspace: 0pt;"><tr><td class="pad"><div style="font-family:'Varela Round', 'Trebuchet MS', Helvetica, sans-serif;text-align:center;" align="center"><div style="height-top: 20px;">&nbsp;</div></div></td></tr></table></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table></body></html>
  `;

  let info = await transporter.sendMail({
      from: '"Truco Arena" <suporte@trucoarena.com>',
      to: to,
      subject: "Token de Reset de Senha",
      html: htmlContent
  });
}

// ******************************************************************************************
// *********************************  ROTA DE RESET DE SENHA  *******************************
// ******************************************************************************************
app.post("/auth/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;

  try {
    const resetEntry = await ResetToken.findOne({
      where: { token },
      include: [{ model: User, as: 'user' }]
    });

    if (!resetEntry || new Date() > resetEntry.expireAt) {
      return res.status(400).json({ msg: "Token inválido ou expirado!" });
    }

    if (resetEntry.user.email !== email) {
      return res.status(400).json({ msg: "E-mail não corresponde ao solicitado para reset!" });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(newPassword, salt);

    await User.update({ password: passwordHash }, {
      where: { id: resetEntry.userId }
    });

    await ResetToken.destroy({
      where: { id: resetEntry.id }
    });

    res.status(200).json({ msg: "Senha redefinida com sucesso!" });
  } catch (error) {
    console.error('Erro ao redefinir senha:', error);
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

app.post("/auth/verify-token", async (req, res) => {
  const { email, token } = req.body;

  try {
    const resetEntry = await ResetToken.findOne({
      where: { token },
      include: [{ model: User, as: 'user' }]
    });

    if (!resetEntry) {
      return res.status(400).json({ valid: false, msg: "Token inválido!" });
    }

    if (new Date() > resetEntry.expireAt) {
      return res.status(400).json({ valid: false, msg: "Token expirado!" });
    }

    if (resetEntry.user.email !== email) {
      return res.status(400).json({ valid: false, msg: "E-mail não corresponde ao solicitado para reset!" });
    }

    res.json({ valid: true });
  } catch (error) {
    console.error('Erro ao verificar token:', error);
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR DADOS POR EMAIL  ***************************
// ******************************************************************************************
app.get("/user/detail/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const user = await User.findOne({
      where: { email },
      attributes: ['username', 'name', 'points', 'balance']
    });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({
      username: user.username,
      name: user.name,
      points: user.points || 0, // Assume 0 if points are undefined
      balance: user.balance || 0 // Assume 0 if balance is undefined
    });
  } catch (error) {
    console.error('Erro ao buscar detalhes do usuário:', error);
    res.status(500).json({ msg: "Erro ao buscar detalhes do usuário" });
  }
});

app.get("/user/username/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const user = await User.findOne({
      where: { email },
      attributes: ['username']
    });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({
      username: user.username
    });
  } catch (error) {
    console.error('Erro ao buscar detalhes do usuário:', error);
    res.status(500).json({ msg: "Erro ao buscar detalhes do usuário" });
  }
});

app.get("/user/balance/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const user = await User.findOne({
      where: { email },
      attributes: ['balance']
    });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({
      balance: user.balance
    });
  } catch (error) {
    console.error('Erro ao buscar o saldo do usuário:', error);
    res.status(500).json({ msg: "Erro ao buscar o saldo do usuário" });
  }
});

app.get("/user/points/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const user = await User.findOne({
      where: { email },
      attributes: ['points']
    });

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    res.status(200).json({
      points: user.points
    });
  } catch (error) {
    console.error('Erro ao buscar pontos do usuário:', error);
    res.status(500).json({ msg: "Erro ao buscar pontos do usuário" });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR O EMAIL E VERIFICAR  ***********************
// ******************************************************************************************
app.get("/auth/check-email/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const user = await User.findOne({
      where: { email }
    });

    res.status(200).json({ exists: !!user });
  } catch (error) {
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR O USERNAME E VERIFICAR  ********************
// ******************************************************************************************
app.get("/auth/check-username/:username", async (req, res) => {
  const { username } = req.params;

  try {
    // Find a user with the specified username
    const user = await User.findOne({
      where: { username }
    });

    if (user) {
      return res.status(200).json({ exists: true });
    } else {
      return res.status(200).json({ exists: false });
    }
  } catch (err) {
    res.status(500).json({ msg: "Error checking username", error: err.message });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE ATUALIZAÇÃO DE SALDO  *******************************
// ******************************************************************************************
app.patch("/admin/:id/balance", async (req, res) => {
  const { id } = req.params;
  const { balance } = req.body;

  // Basic validation
  if (balance === undefined) {
    return res.status(422).json({ msg: "O saldo é obrigatório!" });
  }

  try {
    // Fetch the user by ID
    const user = await User.findByPk(id);

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    // Update the user's balance
    user.balance = balance;
    await user.save();

    res.status(200).json({ msg: "Saldo atualizado com sucesso!", balance: user.balance });
  } catch (err) {
    console.error('Erro ao atualizar o saldo:', err);
    res.status(500).json({ msg: "Erro ao atualizar o saldo" });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE ATUALIZAÇÃO DA LEADERBOARD  *************************
// ******************************************************************************************
app.get('/leaderboard', async (req, res) => {
  try {
      // Usando o método 'findAll' com ordenação e limite
      const topUsers = await User.findAll({
          attributes: ['username', 'points'], // Seleciona apenas as colunas 'username' e 'points'
          order: [['points', 'DESC']], // Ordena os resultados por 'points' em ordem decrescente
          limit: 10 // Limita os resultados a 10 entradas
      });
      res.json(topUsers);
  } catch (err) {
      res.status(500).json({ msg: "Erro ao buscar os dados do leaderboard", error: err });
  }
});
// ******************************************************************************************
// **************************************  CONEXÃO  *****************************************
// ******************************************************************************************
io.on('connection', (socket) => {
  console.log('Um usuário se conectou');

  // Recebendo uma mensagem do cliente
  socket.on('send message', (msg) => {
      console.log('Mensagem recebida:', msg);

      // Aqui você pode processar a mensagem, salvar no banco de dados, etc.

      // Emitindo a mensagem para todos os clientes conectados
      io.emit('receive message', msg);
  });

  // Evento disparado quando o usuário se desconecta
  socket.on('disconnect', () => {
      console.log('Um usuário se desconectou');
  });
});