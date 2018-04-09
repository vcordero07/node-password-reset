"use strict";
exports.DATABASE_URL =
  process.env.DATABASE_URL ||
  global.DATABASE_URL ||
  "mongodb://localhost/node-pwd-reset";
exports.PORT = process.env.PORT || 8080;
exports.JWT_SECRET = process.env.JWT_SECRET;
exports.JWT_EXPIRY = process.env.JWT_EXPIRY || "7d";
exports.SENDGRID_USER = process.env.SENDGRID_USER;
exports.SENDGRID_PWD = process.env.SENDGRID_PWD;
exports.MAIL_FROM = process.env.MAIL_FROM;
