import mongoose from "mongoose";
import {DB_NAME} from "../constants.js";
const connectDB = async () => {
  try {
    const conectionInstace = await mongoose.connect(process.env.MONGODB_URI);
    console.log(`MongoDB Connected Successfully! at Host ${conectionInstace.connection.host}`)
  } catch (error) {
    console.log("MongoDB Connection Error", error);
    process.exit(1)
  }
}

export default connectDB;