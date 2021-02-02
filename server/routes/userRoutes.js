const express = require('express');
const router = express.Router();
const cors = require('cors');
const bcrypt = require('bcrypt');
const mongodb = require('mongodb');

const dbURL = process.env.DB_URL || 'mongodb://127.0.0.1:27017';
const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID;
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const auth = require('../middlewares/authorization');
require('dotenv').config();
router.use(cors());

router.route('/login').post(async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.body.email });
    if (result) {
      let isTrue = await bcrypt.compare(req.body.password, result.password);
      let status = result.status;
      if (isTrue) {
        if (status == true) {
          let token = await jwt.sign(
            { userId: result._id, userName: result.name },
            process.env.PASS,
            { expiresIn: '1h' }
          );

          res
            .status(200)
            .json({ message: 'login success', id: result._id, token });
        } else {
          res.status(200).json({
            message:
              'Please Click on conformation link send to mail to activate your account',
          });
        }
      } else {
        res.status(200).json({ message: 'Login unsuccessful' });
      }
    } else {
      res.status(400).json({ message: 'User not registered' });
    }

    clientInfo.close();
  } catch (error) {
    console.log(error);
  }
});

// forgot password //
router.route('/forgot').post(async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.body.email });
    if (result) {
      var string = Math.random().toString(36).substr(2, 10);
      let transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.SENDER, // generated ethereal user
          pass: process.env.PASS, // generated ethereal password
        },
      });

      // send mail with defined transport object
      let info = await transporter.sendMail({
        from: process.env.SENDER, // sender address
        to: req.body.email, // list of receivers
        subject: 'Reset Password ✔', // Subject line
        text: 'Hello world?', // plain text body
        html: `<a href="http://localhost:5000/auth/${req.body.email}/${string}">Click on this link </a>`, // html body
      });
      await db
        .collection('users')
        .updateOne({ email: req.body.email }, { $set: { string: string } });
      res
        .status(200)
        .json({ message: 'Check your email and reset your password' });
    } else {
      res.status(400).json({ message: 'User not registered' });
    }
  } catch (error) {
    console.log(error);
  }
});

// api for forgotpassword  authentification //
router.route('/auth/:mail/:string').get(async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.params.mail });

    if (result.string == req.params.string) {
      res.redirect(
        `http://localhost:5000/reset.html?${req.params.mail}?${req.params.string}`
      );
      res.status(200).json({ message: 'redirecting to resetpassword page' });
    } else {
      res.status(200).json({ message: 'Link Expired' });
    }

    clientInfo.close();
  } catch (error) {
    console.log(error);
  }
});

router.route('/resetpassword/:mail/:string').put(async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.params.mail });
    if (result.string == req.params.string) {
      let salt = await bcrypt.genSalt(15);
      let hash = await bcrypt.hash(req.body.newPass, salt);
      req.body.newPass = hash;
      let data = await db
        .collection('users')
        .updateOne(
          { email: req.params.mail },
          { $set: { password: req.body.newPass, string: '' } }
        );
      if (data) {
        res.status(200).json({ message: 'Password Updated' });
      }
    }

    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.status(500);
  }
});

module.exports = router;
