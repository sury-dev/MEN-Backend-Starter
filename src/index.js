//require('dotenv').config({path : '../.env'})
import dotenv from 'dotenv';
import mongoose from "mongoose";
import connectDB from "./db/index.js";
import express from 'express';
import { app } from './app.js'; //importing app from app.js

// const app = express();
//Dont need to create another instance of app, we need to call app from app.js to get the routes 

dotenv.config({path : './.env'})

connectDB()
.then(() => {
    const port = process.env.PORT || 8000;
    app.listen(port, () => {
        console.log(`Server is listening on http://localhost:${port}`);
    })
})
.catch((err) => {
    console.log("MongoDB connection failed : error from index.js, error : ", err);
})