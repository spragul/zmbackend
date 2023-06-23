const express = require("express");
const app = express();
const nodemailer = require("nodemailer");
const server = require("http").Server(app);
const io = require("socket.io")(server, {
  cors: {
    origin: "https://main--unrivaled-froyo-c6cf87.netlify.app",
    methods: ["GET", "POST"],
  },
});
const validator = require('validator')
const passport = require("passport");
require("dotenv").config();
const mongoose = require("mongoose");
const session = require("express-session");
const cors = require("cors");
app.use(cors())
const cookieParser = require("cookie-parser");
const { v4: uuidV4 } = require("uuid");
const MemoryStore = require("memorystore")(session);

const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const saltRounds = 10

app.use(
  session({
    secret: process.env.SECRET,
    store: new MemoryStore({
      checkPeriod: 86400000, // prune expired entries every 24h
    }),
    resave: true,
    saveUninitialized: true,
    cookie: { maxAge: 1800000 },
  })
);
app.use(passport.initialize());
app.use(express.json());
app.use(passport.session());
app.use(cookieParser(process.env.SECRET));
const { hashPassword, hashCompare, createToken, validate } = require('./auth')
mongoose.connect(`${process.env.mongooseurl}?retryWrites=true&w=majority`, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.set("useFindAndModify", false);

let UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: {
      type: String,
      required: true,
      lowercase: true,
      validate: (value) => {
        return validator.isEmail(value)
      }
    },
    secret: [String],
    picurL: { type: String, default: 'https://lh3.googleusercontent.com/a/AAcHTtdN2iMTWhGF3486XkfPd3yajm3MPBweYQldVtqj=s96-c' },
    uniqueId: String,
    googleId: { type: Number, required: true },
    rooms: [String], //stores only the roomId of the rooms this user is a part of
    password: { type: String, required: true },
  },
  {
    collection: 'users',
    versionKey: false
  }
)


let User = mongoose.model('users', UserSchema)
//add host,name of room,allowAnyoneToStartTheMeetOrOnlyICanStart(boolean needed)
const roomSchema = new mongoose.Schema({
  name: String,
  roomId: String,
  host: String,
  allowAnyoneToStart: Boolean,
  participants: [{ name: String, uniqueId: String, picurL: String }],
});
const chatSchema = new mongoose.Schema({
  roomDetails: String,
  messages: [{ from: { name: String, uniqueId: String, picurL: String }, dateTime: Date, content: String }],
});
const Chats = new mongoose.model("Chat", chatSchema);

const Rooms = new mongoose.model("room", roomSchema);
const myrooms = mongoose.model("rooms", roomSchema);

app.post('/signup', async (req, res) => {
  try {
    let userdata = await User.findOne({ email: req.body.email })
    if (!userdata) {
      let myroomid = await myrooms.find({}, { roomId: 1, _id: 0 })
      let a = [];
      console.log(myroomid.length)
      if (!(myroomid.length === 0)) {
        for (let i = 0; i < myroomid.length; i++) {
          let b = myroomid[i].roomId;
          a.push(b);
        }
      }else{
        console.log("not working");
      }
      let hashedPassword = await hashPassword(req.body.password)
      req.body.password = hashedPassword
      let uservalue = await User.create({
        name: req.body.name,
        email: req.body.email,
        googleId: req.body.googleId,
        picurL: req.body.picurL,
        uniqueId: uuidV4(),
        password: req.body.password,
        rooms: a
      })
      res.status(201).send({
        message: "User Signup Successfull!",
        data: "true"
      })
    }
    else {
      res.status(400).send({ message: "User Alread Exists!", data: "false" })

    }

  } catch (error) {
    res.status(500).send({ message: "Internal Server Error", error, data: "false" })

  }
})
//login
app.post('/login', async (req, res) => {
  try {
    let userdata = await User.findOne({ email: req.body.email })
    let getdata = userdata._id;
    if (userdata) {
      console.log(userdata)
      //verify the password
      if (await hashCompare(req.body.password, userdata.password)) {
        // create the token
        let token = await createToken({
          name: userdata.name,
          email: userdata.email,
          googleId: userdata.id,
          picurL: userdata.value,
          uniqueId: uuidV4(),
        })
        res.status(200).send({
          message: "User Login Successfull!",
          token: token,
          value: getdata
        })
      }
      else {
        res.status(402).send({ message: "Invalid Credentials" })
      }
    }
    else {
      res.status(400).send({ message: "User Does Not Exists!" })
    }

  } catch (error) {
    res.status(500).send({ message: "Internal Server Error", error })
  }
})
//forgotpassword
app.post('/forgotpassword', async (req, res) => {
  try {
    let user = await User.findOne({ email: req.body.email })
    console.log(user)
    if (!user) {
      res.send({ message: "user not exists!!" })
    }
    const secret = process.env.SECRETKEY + user.password;
    let token = await jwt.sign({ email: user.email, id: user._id }, secret, { expiresIn: '15m' })
    console.log(user._id, token)
    const link = `https://main--unrivaled-froyo-c6cf87.netlify.app/resetpassword/${user._id}/${token}`
    console.log(link)
    var transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.G_MAIL,
        pass: process.env.G_MAIL_PASSWORD,
      }
    });
    let gmailId = await User.findOne({ email: req.body.email })
    var mailOptions = {
      from: process.env.G_MAIL,
      to: gmailId.email,
      subject: 'Reset password',
      text: link
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        res.send(error)
      } else {
        res.send({ message: "meil send" })
      }
    });
  } catch (error) {
    res.send(error);
  }
})
//resetpassword
app.post("/resetpassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  console.log(id, token)
  const { password } = { password: req.body.password };
  const oldUser = await User.findOne({ _id: id });
  if (!oldUser) {
    return res.json({ status: "User Not Exists!!" });
  }
  const secret = process.env.SECRETKEY + oldUser.password;
  try {
    const verify = jwt.verify(token, secret);
    const encryptedPassword = await bcrypt.hash(password, 10);
    await User.updateOne(
      {
        _id: id,
      },
      {
        $set: {
          password: encryptedPassword,
        },
      }
    );

    res.send({ email: verify.email, status: "verified" });
  } catch (error) {
    res.json({ status: "Something Went Wrong" });
  }
});

app.get("/authenticated/:id", async (req, res) => {
  try {
    let value = await User.findOne({ _id: req.params.id })
    if (value) {
      res.send({
        messages: "true",
        data: value
      });

    } else {
      res.send({ message: "false" });
    }
  } catch (error) {
    res.send({ message: "false" });
  }
});
app.get("/ragul/:id", validate, async (req, res) => {
  try {
    let data = await User.findOne({ _id: req.params.id })
    res.send(data);
    console.log(data);
  } catch (error) {
    res.send(error)
  }
})

app.get("/logout", (req, res) => {
  res.send("logged out");
});

const PORT = process.env.PORT || 5000;


app.get("/api/join", (req, res) => {
  res.send({ link: uuidV4() });
});


function pushUserToRoom({ uniqueId, roomId, picurL, name }) {
  Rooms.findOne({ roomId }, (err, room) => {
    if (err) console.log(err);
    if (room) {
      const allUniqueIds = [...new Set([...room.participants.map((x) => x.uniqueId), uniqueId])];
      User.find({ uniqueId: { $in: allUniqueIds } }, (err, users) => {
        const allParticipants = users.map(({ uniqueId, picurL, name }) => {
          return { uniqueId, picurL, name };
        });
        Rooms.findByIdAndUpdate(room._id, { $set: { participants: allParticipants } }, (err, done) => {
          if (err) console.log(err);
        });
      });
    }
  });
  User.findOneAndUpdate({ uniqueId }, { $addToSet: { rooms: roomId } }, (err, user) => {
    if (err) console.log(err);
    if (user) console.log(user);
  });
}

function RemoveUserFromRoom({ uniqueId, roomId }) {
  Rooms.findOne({ roomId }, (err, room) => {
    if (err) console.log(err);
    if (room) {
      const allParticipants = room.participants.filter((x) => x.uniqueId !== uniqueId);
      if (allParticipants.length > 0) {
        const newHost = room.host === uniqueId ? allParticipants[0].uniqueId : room.host;
        Rooms.findByIdAndUpdate(room._id, { $set: { participants: allParticipants, host: newHost } }, (err, done) => {
          if (err) console.log(err);
        });
      } else {
        Rooms.findOneAndDelete({ roomId }, (err, done) => {
          if (err) console.log(err);
        });
        Chats.findOneAndDelete({ roomDetails: roomId }, (err, done) => {
          if (err) console.log(err);
        });
      }
    }
  });
  User.findOneAndUpdate({ uniqueId }, { $pull: { rooms: roomId } }, { new: true }, (err, user) => {
    if (err) console.log(err);
    if (user) {
      console.log(user);
    }
  });
}

//these are some variables that store the essentials that are needed during vide call
let waitingRooms = {};
let getUserIdBySocketId = {};
let getSocketIdByUserId = {};
let getNameFromSocketId = {};
let getUniqueIdFromSocketId = {};
let getSocketIdFromUniqueId = {};

//sockets coding
io.on("connection", (socket) => {
  socket.on("join-all-rooms", (uniqueId) => {
    User.findOne({ uniqueId }, (err, user) => {
      if (err) console.log(err);
      if (user) {
        user.rooms.forEach((room) => {
          socket.join(room);
        });
      }
    });
  });
  //check for room in the database and return either invalid room OR not allowed to join before host
  socket.on("check-valid-room", (roomId, cb) => {
    console.log(roomId);
    if (waitingRooms[roomId] === undefined) {
      Rooms.findOne({ roomId }, (err, room) => {
        if (err) console.log(err);
        if (room) {
          if (room.allowAnyoneToStart === false) cb({ status: "host absent" });
        } else {
          cb({ status: "invalid room" });
        }
      });
    }
  });

  socket.on("req-join-room", (roomId, name, uniqueId) => {
    getNameFromSocketId[socket.id] = name;
    getUniqueIdFromSocketId[socket.id] = uniqueId;
    getSocketIdFromUniqueId[uniqueId] = socket.id;
    socket.to(waitingRooms[roomId]).emit("req-to-join-room", { socketId: socket.id, name }, "join");
    socket.on("disconnect", () => {
      if (getUserIdBySocketId[socket.id] === undefined) {
        socket.to(waitingRooms[roomId]).emit("req-to-join-room", { socketId: socket.id }, "leave");
        delete getNameFromSocketId[socket.id];
        delete getSocketIdFromUniqueId[getUniqueIdFromSocketId[socket.id]];
        delete getUniqueIdFromSocketId[socket.id];
      }
    });
  });

  socket.on("this-user-is-allowed", (socketId, cb) => {
    socket.to(socketId).emit("you-are-admitted");
  });

  socket.on("this-user-is-denied", (socketId) => {
    socket.to(socketId).emit("you-are-denied");
  });

  //this event will create a new room or replace the room(only possible if uuid messes up)
  socket.on("create-room-chat", ({ roomId, uniqueId, picurL, name, meetingName, allowAnyoneToStart }, cb) => {
    Rooms.findOne({ roomId }, (err, room) => {
      if (err) console.log(err);
      if (room) {
        pushUserToRoom({ uniqueId, name, picurL, roomId });
      } else {
        const newRoom = new Rooms({
          name: meetingName,
          roomId,
          participants: [{ uniqueId, name, picurL }],
          host: uniqueId,
          allowAnyoneToStart,
        });
        // newRoom.participants = [{ uniqueId, host, allowAnyoneToStart }];
        newRoom.save();
        const newChat = new Chats({
          roomDetails: roomId,
          messages: [],
        });
        newChat.save();
        if (cb) {
          cb(newRoom);
        }
      }
      User.findOneAndUpdate({ uniqueId }, { $addToSet: { rooms: roomId } }, (err, user) => {
        if (err) console.log(err);
      });
    });
  });

  //replicate below event here also just don't have userId, and not establish the
  //call and only do the database stuff in it where we push participant to the db
  socket.on("join-room-chat", (roomId, { uniqueId, picurL, name }) => {
    pushUserToRoom({ uniqueId, name, picurL, roomId });
  });

  //this does the job of sending the user id and making calls through peerjs
  //also it stores the room in the user and creates other things as needed
  socket.on("join-room", (roomId, userId, { audio, video, picurL, name, uniqueId }) => {
    getUserIdBySocketId[socket.id] = userId;
    getSocketIdByUserId[userId] = socket.id;
    getNameFromSocketId[socket.id] = name;
    getUniqueIdFromSocketId[socket.id] = uniqueId;
    if (waitingRooms[roomId] === undefined) {
      waitingRooms[roomId] = socket.id;
    }
    pushUserToRoom({ uniqueId, name, picurL, roomId });

    socket.join(roomId);
    socket.to(roomId).emit("user-connected", userId, socket.id, { audio, video, picurL, name });
    socket.on("disconnect", () => {
      if (waitingRooms[roomId] === socket.id) {
        delete waitingRooms[roomId];
      }
      socket.to(roomId).emit("user-disconnected", { userId, name: getNameFromSocketId[socket.id], audio, video });
      delete getSocketIdByUserId[getUserIdBySocketId[socket.id]];
      delete getUserIdBySocketId[socket.id];
      delete getNameFromSocketId[socket.id];
      delete getSocketIdFromUniqueId[getUniqueIdFromSocketId[socket.id]];
      delete getUniqueIdFromSocketId[socket.id];
    });
  });

  socket.on("leave-team", ({ roomId, uniqueId }) => {
    RemoveUserFromRoom({ uniqueId, roomId });
  });

  socket.on("get-room-info", (roomId, cb) => {
    Rooms.findOne({ roomId }, (err, room) => {
      if (err) console.log(err);
      if (room) {
        cb(room);
      } else {
        cb(null);
      }
    });
  });

  socket.on("get-chat-data", (roomId, cb) => {
    Chats.findOne({ roomDetails: roomId }, (err, chat) => {
      if (err) console.log(err);
      if (chat) {
        cb(chat);
      } else {
        console.log("not found the chat for the roomid got", roomId);
      }
    });
  });

  socket.on("get-prev-meetings", (uniqueId, cb) => {
    User.findOne({ uniqueId }, (err, user) => {
      if (err) console.log(err);
      if (user) {
        Rooms.find({ roomId: { $in: user.rooms } }, (err, rooms) => {
          cb(rooms);
        });
      }
    });
  });

  socket.on("acknowledge-connected-user", ({ screenShareStatus, socketId, video, audio, userId, roomId, picurL, name }) => {
    socket.to(socketId).emit("update-audio-video-state", { name, picurL, audio, video, userId: getUserIdBySocketId[socket.id], screenShareStatus });
  });
  socket.on("changed-audio-status", ({ status }) => {
    const roomId = Array.from(socket.rooms).pop();
    socket.to(roomId).emit("changed-audio-status-reply", { status, userId: getUserIdBySocketId[socket.id] });
  });
  socket.on("changed-video-status", ({ status }) => {
    const roomId = Array.from(socket.rooms).pop();
    socket.to(roomId).emit("changed-video-status-reply", { status, userId: getUserIdBySocketId[socket.id] });
  });
  //chats handling
  socket.on("send-chat", (chat, MyMeetings) => {
    if (chat.all === true && chat.to && chat.to.roomId) {
      Rooms.findOne({ roomId: chat.to.roomId }, (err, room) => {
        if (room === undefined) console.log("room is undefined");
        // if(room)
        roomUniqueIds = room ? room.participants.map((x) => x.uniqueId) : [];
        if (err) console.log(err);

        User.find({ uniqueId: { $in: roomUniqueIds } }, (err, participants) => {
          if (err) console.log(err);
          const fromId = MyMeetings === undefined ? getUniqueIdFromSocketId[getSocketIdByUserId[chat.from.userId]] : chat.from.uniqueId;
          let from = participants.find((participant) => participant.uniqueId === fromId);
          from = { name: from.name, uniqueId: from.uniqueId, picurL: from.picurL };
          if (room) {
            // if (room.participants)
            Chats.findOneAndUpdate({ roomDetails: room.roomId }, { $push: { messages: { from, content: chat.message, dateTime: chat.dateTime } } }, { new: true }, (err, doc) => {
              if (err) {
                console.log(err);
              }
            });
          } else {
            const room = new Rooms({
              roomId: chat.to.roomId,
              participants: participants.map((participant) => {
                return { name: participant.name, uniqueId: participant.uniqueId, picurL: participant.picurL };
              }),
            });
            room.save();
            User.updateMany({ uniqueId: { $in: roomUniqueIds } }, { $addToSet: { rooms: room.roomId } }, (err, done) => {
              if (err) console.log(err);
            });
            const chatObj = new Chats({
              roomDetails: room.roomId,
              messages: [{ from, content: chat.message, dateTime: chat.dateTime }],
            });
            chatObj.save();
          }
        });
      });
      socket.to(chat.to.roomId).emit("recieved-chat", chat);
    } else {
      if (chat.to && chat.to.userId) {
        const searchableIds =
          MyMeetings === undefined
            ? [getUniqueIdFromSocketId[getSocketIdByUserId[chat.from.userId]], getUniqueIdFromSocketId[getSocketIdByUserId[chat.to.userId]]]
            : [chat.to.uniqueId, chat.from.uniqueId];

        User.find({ uniqueId: { $in: searchableIds } }, (err, participants) => {
          Rooms.findOne({ roomId: { $in: [searchableIds.join(""), searchableIds.reverse().join("")] } }, (err, room) => {
            if (err) console.log(err);
            const fromId = MyMeetings === undefined ? getUniqueIdFromSocketId[getSocketIdByUserId[chat.from.userId]] : [chat.from.uniqueId];
            let from = participants.find((participant) => participant.uniqueId === fromId);
            from = { name: from.name, uniqueId: from.uniqueId, picurL: from.picurL };
            if (room) {
              Chats.findOneAndUpdate({ roomDetails: room.roomId }, { $push: { messages: { from, content: chat.message, dateTime: chat.dateTime } } }, { new: true }, (err, doc) => {
                if (err) {
                  console.log(err);
                }
              });
            } else {
              const room = new Rooms({
                roomId: searchableIds.join(""),
                participants: participants.map((participant) => {
                  return { name: participant.name, uniqueId: participant.uniqueId, picurL: participant.picurL };
                }),
              });
              room.save();
              User.updateMany({ uniqueId: { $in: searchableIds } }, { $push: { rooms: room.roomId } }, (err, done) => {
                if (err) console.log(err);
              });
              const chatObj = new Chats({
                roomDetails: room.roomId,
                messages: [{ from, content: chat.message, dateTime: chat.dateTime }],
              });
              chatObj.save();
            }
          });
        });
        if (MyMeetings === undefined) {
          chat.from.uniqueId === getUniqueIdFromSocketId[getSocketIdByUserId[chat.from.userId]];
        }
        if (MyMeetings === undefined) socket.to(getSocketIdByUserId[chat.to.userId]).emit("recieved-chat", chat);
        if (MyMeetings === true) socket.to(getSocketIdFromUniqueId[chat.to.uniqueId]).emit("recieved-chat", chat);
      }
    }
  });

  //screen share start/stop
  socket.on("stopping-screen-share", ({ userId, roomId }) => {
    socket.to(roomId).emit("stopping-screen-share", userId);
  });
  socket.on("starting-screen-share", ({ userId, roomId }) => {
    socket.to(roomId).emit("starting-screen-share", userId);
  });

});


server.listen(PORT, () => {
  console.log(`listening on port ${PORT}`);
});
