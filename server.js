require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltrounds = 3;
const jwt = require("jsonwebtoken");
const cookie = require("cookie-parser");

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookie());
app.use(express.json());

mongoose.connect(process.env.MONGO, {useNewUrlParser:true, useUnifiedTopology: true, useFindAndModify:false, useCreateIndex: true});

//user
const userSchema = new mongoose.Schema({
    name: String,
    email: {
       type: String,
       required: true,
       unique: true
    },
    password: {
        type: String,
        required: true,
     }
});

const User = mongoose.model("user", userSchema);


//middleware

async function authorise(req, res, next){
    const mytoken = req.cookies.myjwt;

    if(mytoken){
        jwt.verify(mytoken, process.env.ACCESSTOKEN, (err, decoded)=>{
            if(err){
                res.status(401).send("Error in signing in");
            }else{
                console.log("decoded", decoded);
                next();
            }
        });
    }

}


//routes
app.post("/signup", (req,res) => {
    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;
    console.log("check", name, email, password);

    if(email && name && password){
        bcrypt.hash(password, saltrounds, function(err, hashedPword){
            if(!err){
                console.log(hashedPword);

                const newuser = new User({
                    name: name,
                    email: email,
                    password: hashedPword
                });
            
                newuser.save((err) => {
                    if(err){
                        res.send("Error in signing up. Please Try again");
                    }else{
                        res.status(201).send("Sign up completed");
                    }
                });
            }
        });

    }

});

app.post("/login", (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    User.findOne({email: email}, (err, founduser) => {
        if(err){
            res.status(401).send("User not processed");
        }else{
            const id = founduser._id;
            const hashPword = founduser.password;

            bcrypt.compare(password, hashPword, (err, result) => {
                if (!err) {
                  if (result === true) {
                    console.log("CHECK " + founduser);
        
                    const accesstoken = jwt.sign({id: id},process.env.ACCESSTOKEN);

                    res.cookie("myjwt", accesstoken, {httpOnly: true });

                    console.log("TOKEN GIVEN  " + accesstoken);

                    res.status(201).send(accesstoken);
                  }
                  else{
                    res.status(401).send("Error in logging in");
                  }
                }
            }); 
        }
    })
});

app.get("/home", authorise, (req, res) => {
    console.log("YAY");
    res.status(200).send("SUCCESS!");
});


app.listen(process.env.PORT || 3000, function() {
    console.log("Server started on port 3000");
  });