import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fetch from 'node-fetch';
import session from 'express-session';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 7000;

// Conexão com o MongoDB
mongoose.connect('mongodb://localhost:27017/telemetriaDB', {})
  .then(() => console.log('Conectado ao MongoDB'))
  .catch(err => console.error('Erro ao conectar ao MongoDB', err));

// Definição do esquema e modelo de dados de telemetria
const telemetriaSchema = new mongoose.Schema({
  velocidade: { type: Number, required: true },
  velocidadeEixoTraseiro: { type: Number, required: true },
  velocidadeEixoDianteiro: { type: Number, required: true },
  rpmMotor: { type: Number, required: true },
  temperaturaCVT: { type: Number, required: true },
  aceleracaoEixoX: { type: Number, required: true },
  aceleracaoEixoY: { type: Number, required: true },
  aceleracaoEixoZ: { type: Number, required: true },
  freio: { type: Boolean, required: true },
  longitude: { type: Number, required: true },
  latitude: { type: Number, required: true },
  velocidadeGPS: { type: Number, required: true },
  curso: { type: Number, required: true },
  dataCompleta: { type: Date, required: true },
  tensaoBateria: { type: Number, required: true },
  statusDiferencial: { type: Boolean, required: true },
  timestamp: { type: Date, default: Date.now }
});

const Telemetria = mongoose.model('Telemetria', telemetriaSchema);

// Definição do esquema e modelo de usuários
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Middleware para processar JSON
app.use(bodyParser.json());

// Middleware para servir arquivos estáticos
app.use(express.static(join(__dirname, 'public')));

// Middleware para gerenciar sessões
app.use(session({
  secret: 'admin', 
  resave: false,
  saveUninitialized: false
}));

// Rota para registrar um novo usuário administrador (usar postman - http://localhost:7000/register-admin)
app.post('/register-admin', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, isAdmin: true });
    await newUser.save();
    res.status(201).json({ message: 'Usuário administrador registrado com sucesso' });
  } catch (error) {
    console.error('Erro ao registrar usuário administrador:', error.message);
    res.status(500).json({ error: 'Erro ao registrar usuário administrador', details: error.message });
  }
});

// Rota para fazer login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      console.log('Usuário não encontrado:', username);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      req.session.userId = user._id;
      req.session.isAdmin = user.isAdmin;
      console.log('Login realizado com sucesso para:', username);
      return res.status(200).json({ message: 'Login realizado com sucesso', isAdmin: user.isAdmin });
    } else {
      console.log('Credenciais inválidas para:', username);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
  } catch (error) {
    console.error('Erro ao fazer login:', error.message);
    return res.status(500).json({ error: 'Erro ao fazer login', details: error.message });
  }
});

// Middleware para verificar se o usuário está autenticado
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    console.log('Usuário autenticado:', req.session.userId);
    return next();
  } else {
    console.log('Usuário não autenticado');
    res.status(401).json({ error: 'Usuário não autenticado' });
  }
}

// Middleware para verificar se o usuário é administrador
function isAdmin(req, res, next) {
  if (req.session.isAdmin) {
    console.log('Usuário é administrador:', req.session.userId);
    return next();
  } else {
    console.log('Acesso negado para usuário:', req.session.userId);
    res.status(403).json({ error: 'Acesso negado. Esta função requer privilégios de administrador.' });
  }
}

// Rota para fazer logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Erro ao fazer logout:', err.message);
      res.status(500).json({ error: 'Erro ao fazer logout', details: err.message });
    } else {
      console.log('Logout realizado com sucesso');
      res.status(200).json({ message: 'Logout realizado com sucesso' });
    }
  });
});

// Variável para controlar o envio de telemetria
let enviarTelemetria = true;

// Middleware para verificar se o envio de telemetria está ativo
function isTelemetriaAtiva(req, res, next) {
  if (enviarTelemetria) {
    return next();
  } else {
    res.status(503).json({ error: 'Recebimento de telemetria pausado' });
  }
}

// Rota para enviar dados de telemetria da ESP32 (acessível a todos)
app.post('/enviar-telemetria', isTelemetriaAtiva, async (req, res) => {
  try {
    // Verifica o status mais recente do diferencial
    const { statusDiferencial } = await Telemetria.findOne().sort({ timestamp: -1 }).lean().exec();

    const novaTelemetria = new Telemetria({
      ...req.body,
      statusDiferencial: statusDiferencial || false,
    });

    await novaTelemetria.save();
    console.log('Dados de telemetria recebidos e salvos com sucesso');
    res.status(201).json({ message: 'Dados de telemetria recebidos e salvos com sucesso', statusDiferencial: novaTelemetria.statusDiferencial });
  } catch (error) {
    console.error('Erro ao processar dados de telemetria:', error.message);
    res.status(500).json({ error: 'Erro ao processar dados de telemetria', details: error.message });
  }
});

// Rota SSE para enviar dados de telemetria atualizados (acessível a todos)
app.get('/sse-telemetria', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendSseData = async () => {
    try {
      const telemetriaData = await Telemetria.find().sort({ timestamp: -1 }).limit(1).lean().exec();
      if (telemetriaData.length > 0) {
        const dataToSend = JSON.stringify(telemetriaData[0]);
        res.write(`data: ${dataToSend}\n\n`);
      }
    } catch (error) {
      console.error('Erro ao enviar dados SSE', error.message);
    }
  };

  sendSseData();

  const clientId = Date.now();
  res.write(`id: ${clientId}\n`);

  const intervalId = setInterval(sendSseData, 5000);

  req.on('close', () => {
    clearInterval(intervalId);
    console.log('Conexão SSE encerrada:', clientId);
  });
});

// Rota para baixar CSV (acessível a todos)
app.get('/download-csv', async (req, res) => {
  try {
    const telemetriaData = await Telemetria.find().lean().exec();
    const csv = telemetriaData.map(row => Object.values(row).join(',')).join('\n');
    console.log('CSV gerado com sucesso');
    res.header('Content-Type', 'text/csv');
    res.attachment('telemetria.csv');
    res.send(csv);
  } catch (error) {
    console.error('Erro ao baixar CSV:', error.message);
    res.status(500).json({ error: 'Erro ao baixar CSV', details: error.message });
  }
});

// Rotas protegidas (somente administradores)
app.post('/pausar-telemetria', isAuthenticated, isAdmin, (req, res) => {
  enviarTelemetria = false;
  console.log('Recebimento de telemetria pausado');
  res.status(200).json({ message: 'Recebimento de telemetria pausado' });
});

app.post('/retomar-telemetria', isAuthenticated, isAdmin, (req, res) => {
  enviarTelemetria = true;
  console.log('Recebimento de telemetria retomado');
  res.status(200).json({ message: 'Recebimento de telemetria retomado' });
});

app.post('/ligar-led', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const response = await fetch('http://192.168.15.53/led/on');
    const data = await response.text();
    console.log('LED ligado na ESP32');
    res.json({ message: 'LED ligado na ESP32!' });
  } catch (error) {
    console.error('Erro ao ligar o LED na ESP32:', error.message);
    res.status(500).json({ error: 'Erro ao ligar o LED na ESP32' });
  }
});

app.post('/desligar-led', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const response = await fetch('http://192.168.15.53/led/off');
    const data = await response.text();
    console.log('LED desligado na ESP32');
    res.json({ message: 'LED desligado na ESP32!' });
  } catch (error) {
    console.error('Erro ao desligar o LED na ESP32:', error.message);
    res.status(500).json({ error: 'Erro ao desligar o LED na ESP32' });
  }
});

app.post('/blink-led', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const response = await fetch('http://192.168.15.53/blink-led');
    const data = await response.text();
    console.log('LED piscou duas vezes e desligou');
    res.send(data);
  } catch (error) {
    console.error('Erro ao piscar o LED:', error.message);
    res.status(500).json({ error: 'Erro ao piscar o LED' });
  }
});

app.post('/blink-led-thrice', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const response = await fetch('http://192.168.15.53/blink-led-thrice');
    const data = await response.text();
    console.log('LED piscou três vezes e desligou');
    res.json({ message: 'LED piscou três vezes e desligou!' });
  } catch (error) {
    console.error('Erro ao piscar o LED:', error.message);
    res.status(500).json({ error: 'Erro ao piscar o LED' });
  }
});

app.post('/atualizar-diferencial', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { statusDiferencial } = req.body;
    console.log(req.body)
    await Telemetria.updateMany({}, { $set: { statusDiferencial } });
    console.log(`Status do diferencial atualizado para: ${statusDiferencial}`);
    res.status(200).json({ message: `Status do diferencial atualizado para: ${statusDiferencial}` });
  } catch (error) {
    console.error('Erro ao atualizar status do diferencial:', error.message);
    res.status(500).json({ error: 'Erro ao atualizar status do diferencial', details: error.message });
  }
});


// Iniciar o servidor 
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
