import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const connectDB = async () => {
    try{
        const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
        console.log(`MongoDB Connected | Database Host : ${connectionInstance.connection.host}`)
    } catch (err){
        console.log("Error while connecting to MongoDB. Error : ",err);
        process.exit(1);
    }
}

export default connectDB;