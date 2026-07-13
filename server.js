// Install dependencies first: npm install express mongoose bcryptjs jsonwebtoken cors
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors()); // Permits communication from your HTML frontend file

// 1. Connect securely to your cloud database infrastructure (MongoDB Atlas)
// Replace with your real connection string variables in production environments
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/bridge_platform";
const JWT_SECRET = process.env.JWT_SECRET || "super_secure_bridge_signature_key_999";

mongoose.connect(MONGO_URI)
    .then(() => console.log("Secure MongoDB Cluster Linked Successfully."))
    .catch(err => console.error("Database connection failure:", err));

// 2. Define the Scalable User Database Schema Structure
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true }, // Indexed for instant lookups among millions
    password: { type: String, required: true },
    major: { type: String, default: "General" },
    preferredType: { type: String, default: "Full-Time" }
});
const User = mongoose.model('User', UserSchema);

// 3. User Registration Endpoint (Sign Up)
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, major, preferredType } = req.body;
        
        // Prevent duplicate record accounts
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: "Account already exists with this email address." });

        // Hash password before saving to data disk so it is perfectly safe
        const hashedPassword = await bcrypt.hash(password, 12);

        const newUser = new User({
            email,
            password: hashedPassword,
            major: major || "General",
            preferredType: preferredType || "Full-Time"
        });

        await newUser.save();
        res.status(201).json({ message: "Registration successful! You may now access your profile." });
    } catch (err) {
        res.status(500).json({ error: "Server infrastructure error during registration workflow." });
    }
});

// 4. Verification Endpoint (Log In)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "Invalid login credentials." });

        // Evaluate mathematically safe crypt matches
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid login credentials." });

        // Generate a cryptographically signed web token valid for 7 days
        const token = jwt.sign(
            { userId: user._id, major: user.major, preferredType: user.preferredType },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: { email: user.email, major: user.major, preferredType: user.preferredType }
        });
    } catch (err) {
        res.status(500).json({ error: "Authentication system failure." });
    }
});

// Start listening for scale load demands
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Bridge Engine Backend humming on port ${PORT}`));
