var express = require("express"); // Get the module
var app = express(); // Create express by calling the prototype in var express
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { User, validate } = require("./models/userModel");
const auth = require("./auth");
const Token = require("./models/token");
const sendEmail = require("./utils/email");

const dbConnect = require("./db/dbConnect"); // require database connection
// execute database connection
dbConnect();

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: false, limit: "20mb" }));
// app.use("/api/user", User);

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content, Accept, Content-Type, Authorization"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, PATCH, OPTIONS"
  );
  next();
});

// register endpoint
app.post("/register", async (request, response) => {
  try {
    const { error } = validate(request.body);
    if (error) return response.status(400).send(error.details[0].message);

    var email = request.body.email;
    var password = request.body.password;
    var name = request.body.name;

    let user = await User.findOne({ email: email });
    if (user)
      return response.status(400).send("User with given email already exist!");

    // hash the password
    bcrypt
      .hash(password, 10)
      .then((hashedPassword) => {
        // create a new user instance and collect the data
     
        const user = new User({
          name: name,
          email: email,
          password: hashedPassword,
        });
       
        let token = new Token({
          userId: user._id,
          token: require('crypto').randomBytes(64).toString('hex')
        });
        console.log(token.token)
        // save the new user
        user.save();
        token.save();

        const message = `${process.env.BASE_URL}verify/${user.id}/${token.token}`;
        sendEmail(user.email, "Verify Email", message);
    
        response.send("An Email sent to your account please verify");
      })
      // catch error if the password hash isn't successful
      .catch((e) => {
        response.status(500).send({
          message: "Password was not hashed sssfully",
          e,
        });
      });
  } catch (error) {
    response.status(400).send("An error occured");
  }
});

app.post("/login", (request, response) => {
  var email = request.body.email;
  var password = request.body.password;

  User.findOne({ email: email })

    // if email exists
    .then((user) => {
      // compare the password entered and the hashed password found
      bcrypt
        .compare(password, user.password)
        // if the passwords match
        .then((passwordCheck) => {
          // check if password matches
          if (!passwordCheck) {
            return response.status(400).send({
              message: "Passwords does not match",
              error,
            });
          }

          //   create JWT token
          const token = jwt.sign(
            {
              userId: user._id,
              userEmail: user.email,
            },
            "RANDOM-TOKEN",
            { expiresIn: "24h" }
          );
          //   return success response
          response.status(200).send({
            message: "Login Successful",
            email: user.email,
            token,
          });
        }) // catch error if password does not match
        .catch((error) => {
          response.status(400).send({
            message: "Passwords does not match",
            error,
          });
        });
    })
    // catch error if email does not exist
    .catch((e) => {
      response.status(404).send({
        message: "Email not found",
        e,
      });
    });
});

// free endpoint
app.get("/free-endpoint", (request, response) => {
  response.json({ message: "You are free to access me anytime" });
});

// authentication endpoint
app.get("/auth-endpoint", auth, (request, response) => {
  response.json({ message: "You are authorized to access me" });
});


app.get("/verify/:id/:token", async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.params.id });
    if (!user) return res.status(400).send("Invalid link");

    const token = await Token.findOne({
      userId: user._id,
      token: req.params.token,
    });
    if (!token) return res.status(400).send("Invalid link");

    await User.updateOne({ _id: user._id, verified: true });
    await Token.findByIdAndRemove(token._id);

    res.send("email verified sucessfully");
  } catch (error) {
    res.status(400).send("An error occured");
  }
});
module.exports = app;
