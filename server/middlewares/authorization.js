const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  if (req.headers.authorization.length) {
    jwt.verify(req.headers.authorization, process.env.PASS, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: 'Session over, Login again' });
      }
    });
    next();
  } else {
    res.status(401).json({ message: 'token not authorized' });
  }
}
module.exports = auth;
