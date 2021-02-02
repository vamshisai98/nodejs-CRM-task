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

// add employee route by admin / manager //

router.route('/add-user').post(auth, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.body.email });
    if (result) {
      res.status(400).json({ message: 'User already registered' });
      clientInfo.close();
    } else {
      let salt = await bcrypt.genSalt(15);
      let hash = await bcrypt.hash(req.body.password, salt);
      req.body.password = hash;
      await db.collection('users').insertOne(req.body);
      await db
        .collection('users')
        .updateOne({ email: req.body.email }, { $set: { status: true } });
      res.status(200).json({
        message: 'User registered successfully.',
        status: 'sent',
      });
      clientInfo.close();
    }
  } catch (error) {
    console.log(error);
  }
});

// manager login //
router.route('/login').post(async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.body.email });
    if (result.type == 'manager') {
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
            .json({ message: 'manager login success', id: result._id, token });
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
      res.status(400).json({ message: 'You are not allowed to login' });
    }

    clientInfo.close();
  } catch (error) {
    console.log(error);
  }
});

// set user position //
router.route('/position').put(auth, async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db('crm');
    let result = await db
      .collection('users')
      .findOne({ email: req.body.email });
    if (result) {
      var response = await db
        .collection('users')
        .updateOne(
          { email: req.body.email },
          { $set: { position: req.body.position } }
        );

      if (response) {
        res.status(200).json({ message: 'position updated', response });
      } else {
        res.status(200).json({ message: 'position not updated ' });
      }
    } else {
      res.status(200).json({ message: 'users doesnt exist' });
    }

    clientInfo.close();
  } catch (error) {
    console.log(error);
    res.send(500);
  }
});

module.exports = router;
