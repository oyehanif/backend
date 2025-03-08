const express = require('express');
const mongoose =require('mongoose');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const expressValidator = require('express-validator')
require('dotenv').config();
const path = require("path");

//Import routes
const authRoutes = require('./routes/auth') 
const userRoutes = require('./routes/user') 
const app = express();
const cors = require('cors')

const db = process.env.DATABASE;
mongoose
 .connect(
 db,
 { useNewUrlParser: true },

 )
 .then(() => console.log("MongoDB successfully connected"))
 .catch(err => console.log(err));

//middleware
app.use(morgan('dev'))
app.use(bodyParser.json())
app.use(cookieParser());
app.use(expressValidator())
app.use( cors() )
app.use("/public", express.static(path.join(__dirname, "uploads")));

//routes middleware
app.use('/api',authRoutes);
app.use('/api',userRoutes);

const port = process.env.PORT || 8001


app.listen(port,()=>{
    console.log(`working express server ${port}`)
});