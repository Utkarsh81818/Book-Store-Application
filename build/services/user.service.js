"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.newUser = exports.login = void 0;

var _regenerator = _interopRequireDefault(require("@babel/runtime/regenerator"));

var _asyncToGenerator2 = _interopRequireDefault(require("@babel/runtime/helpers/asyncToGenerator"));

var _user = _interopRequireDefault(require("../models/user.model"));

var _bcrypt = _interopRequireDefault(require("bcrypt"));

var _jsonwebtoken = _interopRequireDefault(require("jsonwebtoken"));

var _dotenv = _interopRequireDefault(require("dotenv"));

/* eslint-disable max-len */

/* eslint-disable prettier/prettier */

/* eslint-disable no-unused-vars */
//create new user
var newUser = /*#__PURE__*/function () {
  var _ref = (0, _asyncToGenerator2["default"])( /*#__PURE__*/_regenerator["default"].mark(function _callee(body) {
    var HashedPassword, data;
    return _regenerator["default"].wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.next = 2;
            return _bcrypt["default"].hash(body.password, 10);

          case 2:
            HashedPassword = _context.sent;
            body.password = HashedPassword;
            _context.next = 6;
            return _user["default"].create(body);

          case 6:
            data = _context.sent;
            return _context.abrupt("return", data);

          case 8:
          case "end":
            return _context.stop();
        }
      }
    }, _callee);
  }));

  return function newUser(_x) {
    return _ref.apply(this, arguments);
  };
}(); //Login User


exports.newUser = newUser;

var login = /*#__PURE__*/function () {
  var _ref2 = (0, _asyncToGenerator2["default"])( /*#__PURE__*/_regenerator["default"].mark(function _callee2(body) {
    var check, match, token;
    return _regenerator["default"].wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            _context2.next = 2;
            return _user["default"].findOne({
              email: body.email
            });

          case 2:
            check = _context2.sent;

            if (!check) {
              _context2.next = 15;
              break;
            }

            _context2.next = 6;
            return _bcrypt["default"].compare(body.password, check.password);

          case 6:
            match = _context2.sent;

            if (!match) {
              _context2.next = 12;
              break;
            }

            token = _jsonwebtoken["default"].sign({
              email: check.email,
              id: check._id,
              role: check.role
            }, process.env.SECRET);
            return _context2.abrupt("return", token);

          case 12:
            return _context2.abrupt("return", 'Incorrect Password');

          case 13:
            _context2.next = 16;
            break;

          case 15:
            return _context2.abrupt("return", 'Not Registered Yet');

          case 16:
          case "end":
            return _context2.stop();
        }
      }
    }, _callee2);
  }));

  return function login(_x2) {
    return _ref2.apply(this, arguments);
  };
}();

exports.login = login;