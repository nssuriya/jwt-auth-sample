const express = require('express');
const app = express();
const port = 3000;
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
var cookie = require('cookie');
const passwordHash = require('password-hash');
var jwt = require('jsonwebtoken');
let secret = "somethingsecret";


mongoUrl = "mongodb://127.0.0.1:27017/jwtauth";
let options = {useNewUrlParser: true,useUnifiedTopology: true}

/** ---------- Mongoose operations -------------- */
mongoose.connect(mongoUrl,options);

mongoose.connection.on("error", (error) => {
    console.log("Mongoose connection error : ", JSON.stringify(error));
    process.exit(0);
});

mongoose.connection.on("disconnected", () => {
    console.log("Mongoose connection disconnected : ", new Date());
});

//model for login... move it to a separate file
var LoginSchema = new mongoose.Schema({
    username:{ type:String, unique:true },
    role: String,
    password:String,
    status:String,//can be used for approved-pending
}, {
    timestamps: true,
    writeConcern: {
        j: true,
        wtimeout: 1000
    }
});

const LoginModel = mongoose.model('Login', LoginSchema);
/** ---------- Mongoose operations -------------- */

app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ limit: "5mb", extended: false }));

/** public routes */
app.get('/sample', (req, res) => {
    res.send('Hello World!')
})

app.post('/register', (req, res, next) => {
    try {
        let request = req.body;
        // request.status = "Pending"; // for new users
        request.password = passwordHash.generate(req.body.password);
        var login = new LoginModel(request);
        let response = {
          state:true,
          message: "Login Created for "+ req.body.username,
        }
        login
          .save()
          .then((result) => {
            res.send(response);
          })
          .catch((err) => {
            if(err.code == 11000) {
              let response = {
                state:false,
                message:"Username already exists"
              }
              res.status(409).send(response);
            } else {
              next(err);
            }
          });
      } catch (err) {
        next(err);
      }
});

app.post('/login', (req, res, next) => {
    try {
        let password = req.body.password;
        delete req.body.password;
        LoginModel.findOne(req.body).then((result) => {
            var verify = passwordHash.verify(password,result.password);
            if(verify) {
                let token = jwt.sign({ 
                    username: result.username, 
                    role: result.toObject().role,
                    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
                },secret);
                let response = {
                    state : true,
                    message : "Login Successful",
                    username : result.username,
                    token : token,
                    refreshToken : token,
                }
                res.cookie('token',token).send(response);
            } 
            else {
                res.status(401).send({state:'FAILED',message:"Username/Password is incorrect"});
            }
        })
        .catch((err) => {
            next(err);
        });
    } catch (err) {
        next(err);
    }
})

/** auth logic */
app.use(function(req, res, next) {
  try {
    let cookieJson = cookie.parse(req.headers.cookie); 
    const token = cookieJson.token || req.headers['x-access-token'] || req.query['token'];
    let decode = jwt.verify(token,secret);
    req.username = decode.username;
    req.headers.role = decode.role || 'dummy';
    next();
  } catch(err){
    res.status(401).json(err);
  }
});

/** auth routes */
//same route different data returns
app.get('/authenticated', (req, res) => {
    //role admin
    if(req.headers.role == "admin")
        res.send('Hello Admin User');
    else
        res.send('Hello Non Admin User');

})


/** Middleware to catch 404 */
app.use(function(req, res, next) {
  let err = {
    status: 404,
    message: "Route Not found"
  };
  res.status(err.status).json(err);
});

/** Error handler middleware to handle error */
app.use(function(err, req, res, next) {
  console.log("Handler error : "+err+" "+ new Date());
  // Handle mongoose disconnection and update message accordingly
  const conn = mongoose.connection;
  if (conn.states[conn._readyState] === "disconnected") {
    err.message =
      "There is a problem in connecting to database";
  }
  err.status = err.status || 500;
  res.status(err.status||500).json(err);
});

process.on("uncaughtException", (err) => {
  console.log("Uncaught exception in process :"+process.pid+err);
});

process.on("unhandledRejection", (err, promise) => {
  console.log("Unhandled Rejection at Promise :"+process.pid+err);
});

process.on("SIGINT", () => {
  Logger.info("Received SIGINT");
  mongoose.connection.close(function() {
    console.log("Mongoose default connection disconnected through app termination");
    process.exit(0);
  });
});

app.listen(port, () => {
    console.log(`listening at http://localhost:${port}`)
})

module.exports = app;
