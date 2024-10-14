import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session"
import passport  from "passport";
import { Strategy } from "passport-local";
import flash from "connect-flash";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth20";

const app = express();
const port = 3000;
const saltRounds = 10
env.config();
let userInf

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
    session({
    secret:process.env.SESSION_SECRET,
    resave:false,
    saveUninitialized: true,
    cookie: {}
}))

app.use(passport.initialize())
app.use(passport.session())
app.use(flash());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.use((req, res, next) => {
  res.locals.messages = req.flash(); // Make flash messages available in all templates
  next();
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/submit",(req,res) => {

res.render("submit.ejs")
})

app.get("/secrets", (req, res) => {
 

  if(req.isAuthenticated()){
    const message = userInf[0].secret
    if(message){
      res.render('secrets.ejs',{message:message})
    }
    else {
      res.render('secrets.ejs',{message : "Enter your secret on the submit button"})
    }
  }
  else{
    res.redirect('/login')
  }

});


app.get("/auth/google",
  passport.authenticate("google",{
    scope:["profile","email"]
  })
)


app.get("/auth/google/secrets",
  passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}))



passport.use("google",new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfleURL : "https://www.googleapis.com/oauth2/v3/userinfo",
    }, async (accesToken,refreshToken, profile, cb) => {
      
      const email = profile.emails[0].value
      console.log(email)

        const result = await db.query("SELECT email FROM users WHERE email = ($1)",[email]);
        const user = await db.query("SELECT * FROM users WHERE email = ($1)",[email]);
        
     
        if (result.rows.length === 0){
          
          await db.query("INSERT INTO users (email) VALUES ($1)",[email]);
          const userBase = await db.query("SELECT * FROM users WHERE email = ($1)",[email]);
          userInf = userBase.rows
          return cb(null,userInf)

        } 

        else if(result.rows.length > 0 ){
          const userBase = await db.query("SELECT * FROM users WHERE email = ($1)",[email]);
          userInf = userBase.rows
          return cb(null,userInf)

       }   
       
      }
      
    
))



passport.use("local",new Strategy (async function verify(username,password,cb){
  
  const errorMessage = "Incorrect email"
  const errorMessageTwo = "Incorrect password"
  const errorMessageOne = "Invalid credentials"
  const result = await db.query("SELECT password FROM users WHERE email = ($1)",[username]);
  const userBase = await db.query("SELECT * FROM users WHERE email = ($1)",[username]);
  const user = userBase.rows
  const userPassword = result.rows
  const storedPassword= userPassword.map(item => item.password);


  if(storedPassword.length === 0){
    return cb(null,false,{message:errorMessage})
  }
  
  else if (storedPassword.length !== 0) {
    
    bcrypt.compare(password,storedPassword[0], (err,result) => {
      
      if(err){
       return cb(null, false,{message:errorMessageOne})
        
      }
      else if (result == true){
       
        return cb(null, user)
      }
      else if (result == false) {
        return cb(null, false,{message:errorMessageTwo})
      }
    })
  }


}))


app.post("/submit",async (req,res,next) => {
const secret = req.body.secret
 
  const userId = userInf[0].id
 
  try{
  const result = await db.query("UPDATE users SET secret = $1 WHERE id = $2",[secret,userId])
  const select = await db.query("SELECT * FROM users WHERE id = $1",[userId])
  userInf = select.rows

  return res.redirect("/secrets");

  }
  
catch(error){
  return res.redirect("/submit")
}


});

app.post("/delete",(req,res,next) => {

  passport.authenticate("local", (err, user, info) => {

    
    if (err) { return next(err); }
    req.logOut(user,async (err) => {
        if (err) { return next(err); }
        else {
          const userId = userInf[0].id
          const result = await db.query("DELETE FROM users WHERE id = ($1)",[userId])
          return res.redirect("/"); // Redirect on success
        }
        
    });
})(req, res, next);
  
})

app.post("/logout", (req, res, next) => {
  
  passport.authenticate("local", (err, user, info) => {
    
    if (err) { return next(err); }
    req.logOut(user, (err) => {
        if (err) { return next(err); }
        return res.redirect("/"); // Redirect on success
    });
})(req, res, next);
});

app.post("/login", (req, res, next) => {
  
  passport.authenticate("local", (err, user, info) => {
     
      if (err) { return next(err); }
      if (!user) {
          // If authentication fails, set the error message and redirect back to login
          req.flash('error', info.message); // Use flash messages
          return res.redirect("/login");
      }
      req.logIn(user, async (err) => {
          // Use flash messages
          userInf = user
    
          if (err) { return next(err); }
          return res.redirect("/secrets"); // Redirect on success
      });
  })(req, res, next);

});

app.post("/register", async (req, res) => {
  
  const username = req.body.username
  const password = req.body.password
  
  const hasSpecialChars = password.includes('!');
  const hasCapitalLetter = /[A-Z]/.test(password); 
  const isLongEnough = password.length >= 7;

  if( hasCapitalLetter && hasSpecialChars && isLongEnough)
    
    bcrypt.hash(password, saltRounds, async (error, hash) =>{
      if (error){
        console.log('Error hashing password',error)
      }
      else{
        try {
          const result = await db.query("INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *",[username,hash]);
           userInf = result.rows

          req.logIn(userInf, (err) => {

            if (err) { return next(err); }           
            return res.redirect("/secrets"); // Redirect on success
        });
         
        }
        catch(error){
          const passwordBase = await db.query("SELECT password FROM users WHERE email = ($1) ",[username]);
         
          const passwordUser = passwordBase.rows[0].password
          console.log(passwordUser)
          
          if(passwordUser === null){
            const result = await db.query("UPDATE users SET password = $1 WHERE email = $2 RETURNING *",[hash,username]);
            userInf = result.rows
            console.log(userInf)
            
            req.logIn(userInf, (err) => {
              
              if (err) { return next(err); }             
              return res.redirect("/secrets"); // Redirect on success
          });
          }
          else if (passwordUser !== null){

            if (error.code === '23505') { // Unique violation error code
              console.error('Email already exists:', error.detail);
              const errorMsg = "Email already exists"
              res.render('register.ejs',{errorMessage:errorMsg})
            } else {
                console.error('Database error:', error);
                res.status(500).send('Internal server error. Please try again later.');
            }
          }
         
        }      
      }
    })

    
    else {
      const errorMsg = "password must containt 7 letters a ! and cappital letter"
      console.log("password must containt 7 letters a ! and cappital letter")
      res.render('register.ejs',{errorMessageTwo:errorMsg})
    }

    });


app.get("/login", (req, res) => {
  
  if(req.isAuthenticated()){
    res.render('secrets.ejs')
  }
  else{
    res.render('login.ejs')
  }

});

app.get("/register", (req, res) => {
  if(req.isAuthenticated()){
    res.render('secrets.ejs')
  }
  else{
    res.render('register.ejs')
  }
});



passport.serializeUser((user, cb)=>{
  cb(null, user)
})

passport.deserializeUser((user, cb)=>{
 
  cb(null, user)
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});