const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Attempt to connect using our secret link from the .env file
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB Connected Successfully.');
  } catch (error) {
    console.error('Database connection failed:', error.message);
    process.exit(1); // Stop the server entirely if connection fails
  }
};

module.exports = connectDB;
