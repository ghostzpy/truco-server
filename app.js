// ******************************************************************************************
// *************************************  DEPENDENCIAS  *************************************
// ******************************************************************************************
require("dotenv").config();
const cors = require('cors');
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server, {
    cors: {
        origin: "http://127.0.0.1:5500", // Permitir todos os domínios, ajuste conforme necessário
        methods: ["GET", "POST"]
    }
});


// models
const User = require("./User.js");

// Config JSON response
app.use(express.json());

// Habilita CORS para todas as rotas
app.use(cors());

// ******************************************************************************************
// *************************************  ROTA ABERTA  **************************************
// ******************************************************************************************
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a API TRUCO ARENA!" });
});

// ******************************************************************************************
// **********************************  ROTA PRIVADA USUÁRIO  *******************************
// ******************************************************************************************
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  res.status(200).json({ user });
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
app.post("/auth/register", async (req, res) => {
  const { name, email, password, username } = req.body;

  // check if user exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" });
  }

  // check if username exists
  const usernameExists = await User.findOne({ username });
  if (usernameExists) {
    return res.status(422).json({ msg: "O nome de usuário já está em uso!" });
  }

  // create password hash
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Criar usuário
  const user = new User({
    name,
    email,
    password: passwordHash,
    username
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});

// ******************************************************************************************
// *********************************  ROTA DE LOGIN  ****************************************
// ******************************************************************************************
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  // check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  try {
    const secret = process.env.JWT_SECRET;

    const token = jwt.sign(
      { id: user._id },
      secret,
      { expiresIn: '1h' }
    );

    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    res.status(500).json({ msg: error });
  }
});

app.get("/user/data/:email", async (req, res) => {
  const { email } = req.params;
  try {
    // Buscar o usuário pelo email e selecionar campos específicos
    const user = await User.findOne({ email: email }).select('points _id username email');
    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }
    // Retornar os dados do usuário em um JSON
    res.status(200).json({
      points: user.points,
      objectId: user._id,
      username: user.username,
      email: user.email
    });
  } catch (error) {
    console.error('Erro ao buscar os dados do usuário:', error);
    res.status(500).json({ msg: "Erro interno do servidor" });
  }
});

// ******************************************************************************************
// *********************************  ROTA DE RESET DE SENHA  *******************************
// ******************************************************************************************
app.post("/auth/reset-password", async (req, res) => {
  const { senhaAntiga, newPassword } = req.body;
  const token = req.headers.authorization?.split(' ')[1]; // Supondo que o token seja enviado no header

  if (!newPassword || !token) {
      return res.status(422).json({ msg: "Nova senha e token são obrigatórios!" });
  }

  try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Encontrar o usuário com base no ID extraído do token
      const user = await User.findById(decoded.id);

      if (!user || !user.password) { // Verifique também se o usuário tem uma senha definida
          return res.status(404).json({ msg: "Usuário não encontrado ou senha não definida!" });
      }

      // Verificar se a senha antiga está correta
      if (!senhaAntiga) {
          return res.status(422).json({ msg: "Senha antiga é necessária!" });
      }
      
      const senhaValida = await bcrypt.compare(senhaAntiga, user.password);
      if (!senhaValida) {
          return res.status(422).json({ msg: "Senha antiga inválida!" });
      }

      // Criar hash da nova senha
      const salt = await bcrypt.genSalt(12);
      const passwordHash = await bcrypt.hash(newPassword, salt);

      // Atualizar senha do usuário
      user.password = passwordHash;
      await user.save();

      res.status(200).json({ msg: "Senha redefinida com sucesso!" });
  } catch (error) {
      console.error(error);
      res.status(401).json({ msg: "Token inválido ou expirado!", error: error.message });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR DADOS POR EMAIL  ***************************
// ******************************************************************************************
app.get("/user/detail/:email", async (req, res) => {
  const email = req.params.email;

  try {
      // Buscar o usuário pelo email e retornar apenas os campos específicos
      const user = await User.findOne({ email }).select('username name points balance');

      if (!user) {
          return res.status(404).json({ msg: "Usuário não encontrado!" });
      }

      // Retornar os dados específicos em um JSON
      res.status(200).json({
          username: user.username,
          name: user.name,
          points: user.points || notfound, // Retorna 0 se 'points' não estiver definido
          balance: user.balance || notfound // Retorna 0 se 'balance' não estiver definido
      });
  } catch (error) {
      console.error('Erro ao buscar detalhes do usuário:', error);
      res.status(500).json({ msg: "Erro ao buscar detalhes do usuário" });
  }
});

app.get("/user/username/:email", async (req, res) => {
  const email = req.params.email;

  try {
      // Buscar o usuário pelo email e retornar apenas os campos específicos
      const user = await User.findOne({ email }).select('username');

      if (!user) {
          return res.status(404).json({ msg: "Usuário não encontrado!" });
      }

      // Retornar os dados específicos em um JSON
      res.status(200).json({
          username: user.username
      });
  } catch (error) {
      console.error('Erro ao buscar detalhes do usuário:', error);
      res.status(500).json({ msg: "Erro ao buscar detalhes do usuário" });
  }
});

app.get("/user/balance/:email", async (req, res) => {
  const email = req.params.email;

  try {
      // Buscar o usuário pelo email e retornar apenas o campo balance
      const user = await User.findOne({ email }).select('balance');

      if (!user) {
          return res.status(404).json({ msg: "Usuário não encontrado!" });
      }

      // Retornar os dados específicos em um JSON
      res.status(200).json({
          balance: user.balance
      });
  } catch (error) {
      console.error('Erro ao buscar o saldo do usuário:', error);
      res.status(500).json({ msg: "Erro ao buscar o saldo do usuário" });
  }
});

app.get("/user/points/:email", async (req, res) => {
  const email = req.params.email;

  try {
      // Buscar o usuário pelo email e retornar apenas o campo balance
      const user = await User.findOne({ email }).select('points');

      if (!user) {
          return res.status(404).json({ msg: "Usuário não encontrado!" });
      }

      // Retornar os dados específicos em um JSON
      res.status(200).json({
        points: user.points
      });
  } catch (error) {
      console.error('Erro ao buscar o saldo do usuário:', error);
      res.status(500).json({ msg: "Erro ao buscar o saldo do usuário" });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR O EMAIL E VERIFICAR  ***********************
// ******************************************************************************************
app.get("/auth/check-email/:email", async (req, res) => {
  const email = req.params.email;

  const user = await User.findOne({ email });
  if (user) {
    return res.status(200).json({ exists: true });
  } else {
    return res.status(200).json({ exists: false });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR O USERNAME E VERIFICAR  ********************
// ******************************************************************************************
app.get("/auth/check-username/:username", async (req, res) => {
  const username = req.params.username;

  const user = await User.findOne({ username: new RegExp(`^${username}$`, 'i') });
  if (user) {
    return res.status(200).json({ exists: true });
  } else {
    return res.status(200).json({ exists: false });
  }
});

// ******************************************************************************************
// ***************************  ROTA DE PROCURAR VIA MAIL E VERIFICAR  **********************
// ******************************************************************************************
app.get("/user/email/:email", checkToken, async (req, res) => {
  const email = req.params.email;

  const user = await User.findOne({ email }).select("-password");
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  res.status(200).json({ user });
});

// ******************************************************************************************
// ***************************  ROTA DE ATUALIZAÇÃO DE SALDO  *******************************
// ******************************************************************************************
app.patch("/admin/:id/balance", async (req, res) => {
  const id = req.params.id;
  const { balance } = req.body;

  // Validação básica
  if (balance === undefined) {
    return res.status(422).json({ msg: "O saldo é obrigatório!" });
  }

  try {
    // Procurar usuário pelo ID
    const user = await User.findById(id);

    if (!user) {
      return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    // Atualizar saldo do usuário
    user.balance = balance;
    await user.save();

    res.status(200).json({ msg: "Saldo atualizado com sucesso!", balance: user.balance });
  } catch (err) {
    res.status(500).json({ msg: "Erro ao atualizar o saldo" });
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
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

mongoose.connect(
  `mongodb+srv://${dbUser}:${dbPassword}@apptrucoarena.dmi0cye.mongodb.net/?retryWrites=true&w=majority&appName=apptrucoarena`
)
.then(() => {
  console.log("💤 Conectou ao banco!");
  server.listen(3000, () => console.log(`Servidor rodando na porta 3000`));
})
.catch((err) => console.error('Erro ao conectar ao banco de dados:', err));