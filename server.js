if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const { saveAs } = require("file-saver");
const XLSX = require("xlsx");

app.set("view-engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: false
  })
);
app.use(methodOverride("_method"));
app.use(express.static(__dirname + "/views"));

/* MONGOOSE SETUP */

const mongoose = require("mongoose");
mongoose.connect("mongodb://localhost:27017/drugdecider");

const Schema = mongoose.Schema;
const UserDetail = new Schema({
  username: String,
  password: String
});

const SubmissionSchema = new mongoose.Schema({
  info: { type: mongoose.Schema.Types.ObjectId, ref: "UserInfo" },
  PANSS: { type: mongoose.Schema.Types.ObjectId, ref: "PANSS" },
  userScores: { type: mongoose.Schema.Types.ObjectId, ref: "userScores" }
});

const ScoresSchema = new mongoose.Schema({
  activeSocialAvoidance: { type: Number, required: true },
  anxiety: { type: Number, required: true },
  bluntedAffect: { type: Number, required: true },
  conceptualDisorganisation: { type: Number, required: true },
  delusions: { type: Number, required: true },
  depression: { type: Number, required: true },
  difficultyInAbstractThinking: { type: Number, required: true },
  disorientation: { type: Number, required: true },
  disturbanceOfVolition: { type: Number, required: true },
  emotionalWithdrawal: { type: Number, required: true },
  excitement: { type: Number, required: true },
  grandiosity: { type: Number, required: true },
  guiltFeelings: { type: Number, required: true },
  hallucinatoryBehaviour: { type: Number, required: true },
  hostility: { type: Number, required: true },
  lackOfJudgementAndInsight: { type: Number, required: true },
  lackOfSpontaneityAndFlowOfConversation: { type: Number, required: true },
  mannerismsAndPosturing: { type: Number, required: true },
  motorRetardation: { type: Number, required: true },
  passiveApatheticSocialWithdrawal: { type: Number, required: true },
  poorAttention: { type: Number, required: true },
  poorImpulseControl: { type: Number, required: true },
  poorRapport: { type: Number, required: true },
  preoccupation: { type: Number, required: true },
  somaticConcern: { type: Number, required: true },
  stereotypedThinking: { type: Number, required: true },
  suspiciousnessPersecution: { type: Number, required: true },
  tension: { type: Number, required: true },
  uncooperativeness: { type: Number, required: true },
  unusualThoughtContent: { type: Number, required: true }
});

const InfoSchema = new mongoose.Schema({
  bp: { type: Number, required: true },
  BMI: { type: Number, required: true },
  DX: { type: String, required: true },
  DXAge: { type: Number, required: true },
  country: { type: String, required: true },
  age: { type: Number, required: true },
  gender: { type: String, required: true, enum: ["M", "F"] }
});

this.scoresMap = mongoose.model("scores", ScoresSchema);
this.infoMap = mongoose.model("info", InfoSchema);
this.submissionMap = mongoose.model("submission", SubmissionSchema);
const UserDetails = mongoose.model("users", UserDetail, "users");

/*  PASSPORT SETUP  */

const passport = require("passport");
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, cb) {
  cb(null, user);
});

passport.deserializeUser(function(id, cb) {
  UserDetails.findById(id, function(err, user) {
    cb(err, user);
  });
});

/* PASSPORT LOCAL AUTHENTICATION */

const LocalStrategy = require("passport-local").Strategy;

passport.use(
  "local",
  new LocalStrategy((username, password, done) => {
    UserDetails.findOne(
      {
        username: username
      },
      async (err, user) => {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "Invalid Username or Password" });
        }
        if (await bcrypt.compare(password, user.password)) {
          return done(null, user);
        }
        return done(null, false, { message: "Invalid Username or Password" });
      }
    );
  })
);

app.get("/", checkAuthenticated, (req, res) => {
  req.flash("info_i", req.session.messagei);
  req.session.messagei = "";
  res.render("index.ejs", { name: req.user.username });
});

app.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
  })
);

app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.get("/changePassword", checkAuthenticated, (req, res) => {
  res.render("change-password.ejs", { message: req.session.message });
});

app.post("/changePassword", checkAuthenticated, async (req, res) => {
  try {
    if (await bcrypt.compare(req.body.oldPassword, req.user.password)) {
      //check if new passwords are the same
      if (req.body.newPassword.localeCompare(req.body.confirmPassword) == 0) {
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        UserDetails.update(
          { _id: req.user._id },
          { $set: { password: hashedPassword } },
          function(err) {
            if (err) {
              req.session.message = "could not update password";
              throw "could not update password";
            }
          }
        );
        req.session.messagei = "Password successfully updated.";
      } else {
        req.session.message = "New passwords do not match.";
        throw "bad new password";
      }
      res.redirect("/");
    } else {
      req.session.message = "Old password does not match.";
      throw "old password doesn't match";
    }
  } catch (e) {
    req.flash("info_c", req.session.message);
    req.session.message = "";
    res.redirect("/changePassword");
  }
});

app.delete("/logout", (req, res) => {
  req.logOut();
  res.redirect("/login");
});

app.get("/getexcel", checkAuthenticated, (req, res) => {
  getDataExcel();
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

async function retrieveData() {
  var submissionCursor = await this.submissionMap.find();

  return submissionCursor.map(async submission => {
    var infoJSON = await this.infoMap.findById(submission.info);
    var PANSSJSON = await this.scoresMap.findById(submission.PANSS);
    var userScoresJSON = await this.scoresMap.findById(submission.userScores);

    return {
      info: JSON.stringify(infoJSON),
      PANSS_scores: JSON.stringify(PANSSJSON),
      user_scores: JSON.stringify(userScoresJSON)
    };
  });
}

function getDataExcel(req, res, next) {
  var data = retrieveData();

  let arr = [
    [
      "Gender",
      "Age",
      "Country",
      "DXAge",
      "DX",
      "BMI",
      "bp",
      "PANSS_ACTIVESOCIALAVOIDANCE",
      "PANSS_ANXIETY",
      "PANSS_BLUNTEDAFFECT",
      "PANSS_CONCEPTUALDISORGANISATION",
      "PANSS_DELUSIONS",
      "PANSS_DEPRESSION",
      "PANSS_DIFFICULTYINABSTRACTTHINKING",
      "PANSS_DISORIENTATION",
      "PANSS_DISTURBANCEOFVOLITION",
      "PANSS_EMOTIONALWITHDRAWAL",
      "PANSS_EXCITEMENT",
      "PANSS_GRANDIOSITY",
      "PANSS_GUILTFEELINGS",
      "PANSS_HALLUCINATORYBEHAVIOUR",
      "PANSS_HOSTILITY",
      "PANSS_LACKOFJUDGEMENTANDINSIGHT",
      "PANSS_LACKOFSPONTANEITYANDFLOWOFCONVERSATION",
      "PANSS_MANNERISMSANDPOSTURING",
      "PANSS_MOTORRETARDATION",
      "PANSS_PASSIVEAPATHETICSOCIALWITHDRAWAL",
      "PANSS_POORATTENTION",
      "PANSS_POORIMPULSECONTROL",
      "PANSS_POORRAPPORT",
      "PANSS_PREOCCUPATION",
      "PANSS_SOMATICCONCERN",
      "PANSS_STEREOTYPEDTHINKING",
      "PANSS_SUSPICIOUSNESSPERSECUTION",
      "PANSS_TENSION",
      "PANSS_UNCOOPERATIVENESS",
      "PANSS_UNUSUALTHOUGHTCONTENT",
      "USER_ACTIVESOCIALAVOIDANCE",
      "USER_ANXIETY",
      "USER_BLUNTEDAFFECT",
      "USER_CONCEPTUALDISORGANISATION",
      "USER_DELUSIONS",
      "USER_DEPRESSION",
      "USER_DIFFICULTYINABSTRACTTHINKING",
      "USER_DISORIENTATION",
      "USER_DISTURBANCEOFVOLITION",
      "USER_EMOTIONALWITHDRAWAL",
      "USER_EXCITEMENT",
      "USER_GRANDIOSITY",
      "USER_GUILTFEELINGS",
      "USER_HALLUCINATORYBEHAVIOUR",
      "USER_HOSTILITY",
      "USER_LACKOFJUDGEMENTANDINSIGHT",
      "USER_LACKOFSPONTANEITYANDFLOWOFCONVERSATION",
      "USER_MANNERISMSANDPOSTURING",
      "USER_MOTORRETARDATION",
      "USER_PASSIVEAPATHETICSOCIALWITHDRAWAL",
      "USER_POORATTENTION",
      "USER_POORIMPULSECONTROL",
      "USER_POORRAPPORT",
      "USER_PREOCCUPATION",
      "USER_SOMATICCONCERN",
      "USER_STEREOTYPEDTHINKING",
      "USER_SUSPICIOUSNESSPERSECUTION",
      "USER_TENSION",
      "USER_UNCOOPERATIVENESS",
      "USER_UNUSUALTHOUGHTCONTENT"
    ]
  ];

  let patients = [];

  for (let i = 0; i < data.length; i++) {
    let patient = data[i];
    let temparr = [];
    temparr.push(patient.info.gender);
    temparr.push(patient.info.age);
    temparr.push(patient.info.country);
    temparr.push(patient.info.DXAge);
    temparr.push(patient.info.DX);
    temparr.push(patient.info.BMI);
    temparr.push(patient.info.bp);

    temparr.push(patient.PANSS_scores.activeSocialAvoidance);
    temparr.push(patient.PANSS_scores.anxiety);
    temparr.push(patient.PANSS_scores.bluntedAffect);
    temparr.push(patient.PANSS_scores.conceptualDisorganisation);
    temparr.push(patient.PANSS_scores.delusions);
    temparr.push(patient.PANSS_scores.depression);
    temparr.push(patient.PANSS_scores.difficultyInAbstractThinking);
    temparr.push(patient.PANSS_scores.disorientation);
    temparr.push(patient.PANSS_scores.disturbanceOfVolition);
    temparr.push(patient.PANSS_scores.emotionalWithdrawal);
    temparr.push(patient.PANSS_scores.excitement);
    temparr.push(patient.PANSS_scores.grandiosity);
    temparr.push(patient.PANSS_scores.guiltFeelings);
    temparr.push(patient.PANSS_scores.hallucinatoryBehaviour);
    temparr.push(patient.PANSS_scores.hostility);
    temparr.push(patient.PANSS_scores.lackOfJudgementAndInsight);
    temparr.push(patient.PANSS_scores.lackOfSpontaneityAndFlowOfConversation);
    temparr.push(patient.PANSS_scores.mannerismsAndPosturing);
    temparr.push(patient.PANSS_scores.motorRetardation);
    temparr.push(patient.PANSS_scores.passiveApatheticSocialWithdrawal);
    temparr.push(patient.PANSS_scores.poorAttention);
    temparr.push(patient.PANSS_scores.poorImpulseControl);
    temparr.push(patient.PANSS_scores.poorRapport);
    temparr.push(patient.PANSS_scores.preoccupation);
    temparr.push(patient.PANSS_scores.somaticConcern);
    temparr.push(patient.PANSS_scores.stereotypedThinking);
    temparr.push(patient.PANSS_scores.suspiciousnessPersecution);
    temparr.push(patient.PANSS_scores.tension);
    temparr.push(patient.PANSS_scores.uncooperativeness);
    temparr.push(patient.PANSS_scores.unusualThoughtContent);

    temparr.push(patient.user_scores.activeSocialAvoidance);
    temparr.push(patient.user_scores.anxiety);
    temparr.push(patient.user_scores.bluntedAffect);
    temparr.push(patient.user_scores.conceptualDisorganisation);
    temparr.push(patient.user_scores.delusions);
    temparr.push(patient.user_scores.depression);
    temparr.push(patient.user_scores.difficultyInAbstractThinking);
    temparr.push(patient.user_scores.disorientation);
    temparr.push(patient.user_scores.disturbanceOfVolition);
    temparr.push(patient.user_scores.emotionalWithdrawal);
    temparr.push(patient.user_scores.excitement);
    temparr.push(patient.user_scores.grandiosity);
    temparr.push(patient.user_scores.guiltFeelings);
    temparr.push(patient.user_scores.hallucinatoryBehaviour);
    temparr.push(patient.user_scores.hostility);
    temparr.push(patient.user_scores.lackOfJudgementAndInsight);
    temparr.push(patient.user_scores.lackOfSpontaneityAndFlowOfConversation);
    temparr.push(patient.user_scores.mannerismsAndPosturing);
    temparr.push(patient.user_scores.motorRetardation);
    temparr.push(patient.user_scores.passiveApatheticSocialWithdrawal);
    temparr.push(patient.user_scores.poorAttention);
    temparr.push(patient.user_scores.poorImpulseControl);
    temparr.push(patient.user_scores.poorRapport);
    temparr.push(patient.user_scores.preoccupation);
    temparr.push(patient.user_scores.somaticConcern);
    temparr.push(patient.user_scores.stereotypedThinking);
    temparr.push(patient.user_scores.suspiciousnessPersecution);
    temparr.push(patient.user_scores.tension);
    temparr.push(patient.user_scores.uncooperativeness);
    temparr.push(patient.user_scores.unusualThoughtContent);

    patients.push(temparr);
  }

  arr.concat(patients);
  let ws = XLSX.utils.aoa_to_sheet(arr);
  let wb = XLSX.utils.book_new();
  wb.SheetNames.push("PANSS Info");
  wb.Sheets["PANSS Info"] = ws;

  let wbout = XLSX.write(wb, { bookType: "xlsx", type: "binary" });
  XLSX.writeFile(wbout, "panss.xlsx");
  // var buf = new ArrayBuffer(wbout.length); //convert s to arrayBuffer
  // var view = new Uint8Array(buf); //create uint8array as viewer
  // for (var i = 0; i < wbout.length; i++) view[i] = wbout.charCodeAt(i) & 0xff; //convert to octet

  // var blob = new Blob([buf], { type: "application/octet-stream" });

  // saveAs(blob, "panss.xlsx");
}

app.listen(3000);
