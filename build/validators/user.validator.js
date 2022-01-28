"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.newUserValidator = exports.forgot = void 0;

var _joi = _interopRequireDefault(require("@hapi/joi"));

/* eslint-disable prettier/prettier */
var newUserValidator = function newUserValidator(req, res, next) {
  var schema = _joi["default"].object({
    firstName: _joi["default"].string().min(2).required().pattern(new RegExp('^[A-Za-z]{1}[a-z]{1,}$')),
    lastName: _joi["default"].string().min(2).required().pattern(new RegExp('^[A-Za-z]{1}[a-z]{1,}$')),
    email: _joi["default"].string().pattern(new RegExp('^[a-zA-z]{2}([+-_ .]*[a-zA-Z0-9]+)*[@][a-zA-z0-9]+(.[a-z]{2,3})*$')).required(),
    password: _joi["default"].string().pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})')).required(),
    role: _joi["default"].string()
  });

  var _schema$validate = schema.validate(req.body),
      error = _schema$validate.error,
      value = _schema$validate.value;

  if (error) {
    next(error);
  } else {
    req.validatedBody = value;
    next();
  }
};

exports.newUserValidator = newUserValidator;

var forgot = function forgot(req, res, next) {
  var schema = _joi["default"].object({
    email: _joi["default"].string().pattern(new RegExp('^[a-zA-z]{2}([+-_ .]*[a-zA-Z0-9]+)*[@][a-zA-z0-9]+(.[a-z]{2,3})*$')).required()
  });

  var _schema$validate2 = schema.validate(req.body),
      error = _schema$validate2.error,
      value = _schema$validate2.value;

  if (error) {
    next(error);
  } else {
    req.validatedBody = value;
    next();
  }
};

exports.forgot = forgot;