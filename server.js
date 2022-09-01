const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./data/db.json');
const userdb = JSON.parse(fs.readFileSync('./data/users.json', 'UTF-8'));
server.use(jsonServer.defaults());

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());

const SECRET_KEY = '123456789';
const expiresIn = '12h';

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => (decode !== undefined ? decode : err));
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return (
    userdb.users.findIndex((user) => user.email === email && user.password === password) !== -1
  );
}

function findUser({ email }) {
  return userdb.users.find((user) => user.email === email);
}

server.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (isAuthenticated({ email, password }) === false) {
    const status = 401;
    const message = 'Email ou senha inválida';
    res.status(status).json({ status, message });
    return;
  }
  const access_token = createToken({ email, password });
  const user = findUser({ email });

  res.status(200).json({
    access_token,
    user: {
      id: user.id,
      name: user.name,
    },
  });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  const isPrivateRoute = req.method === 'POST' && req.baseUrl.includes('/products');

  if (!isPrivateRoute) {
    next();
    return;
  }

  const isValidReader =
    req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer';

  if (isValidReader) {
    const status = 401;
    const message = 'Cabeçalho de autorização incorreto';
    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(' ')[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = 'Erro: access_token inválido';
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(8081, () => {
  console.log('Run Auth API Server: http://localhost:8081');
});

server.use('/api', router);
