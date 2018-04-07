var express = require("express");
var path = require("path");
// var favicon = require("static-favicon");
var logger = require("morgan");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");

var app = express();

// Middleware
app.set("port", process.env.PORT || 3000);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
// app.use(favicon());
app.use(logger("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// Routes
app.get("/", function(req, res) {
  res.render("index", { title: "Express" });
});

app.listen(app.get("port"), function() {
  console.log("Express server listening on port " + app.get("port"));
});
