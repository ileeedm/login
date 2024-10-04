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

app.get("/secrets", (req, res) => {
  

  if(req.isAuthenticated()){
    res.render('secrets.ejs')
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
      console.log(accesToken)
      console.log(profile.emails[0].value)
      const email = profile.emails[0].value
      try{
        const result = await db.query("SELECT email FROM users WHERE email = ($1)",[email]);
        const user = result.rows
        const baseEmail = result.rows[0].email
        console.log(user)
        
        if(email === baseEmail){
          return cb(null,user)
         }
         
      }

      catch(err){
        console.log("User does not exist in database")
        if(err){
          return cb(null, false)
        }
      }
    
    }
))



passport.use("local",new Strategy (async function verify(username,password,cb){
  
  const errorMessage = "Incorrect email"
  const errorMessageTwo = "Incorrect password"
  const result = await db.query("SELECT password FROM users WHERE email = ($1)",[username]);
  const user = result.rows
  const storedPassword= user.map(item => item.password);
  

  if(storedPassword.length === 0){
    return cb(null,false,{message:errorMessage})
  }
  
  else if (storedPassword.length !== 0) {
    
    bcrypt.compare(password,storedPassword[0], (err,result) => {
      
      if(err){
       return cb("Error in bycrpit",err)
        
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
      req.logIn(user, (err) => {
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
          const user = result.rows[0]
          console.log(user)
          req.logIn(user, (err) => {
            if (err) { return next(err); }
            return res.redirect("/secrets"); // Redirect on success
        });
         
        }
        catch(error){
          
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
    })

    
    else {
      const errorMsg = "password must containt 7 letters a ! and cappital letter"
      console.log("password must containt 7 letters a ! and cappital letter")
      res.render('register.ejs',{errorMessageTwo:errorMsg})
    }

    });


passport.serializeUser((user, cb)=>{
  cb(null, user)
})

passport.deserializeUser((user, cb)=>{
  console.log(user)
  cb(null, user)
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});