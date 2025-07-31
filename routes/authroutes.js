const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../model/userSchema');

const jwt = require('jsonwebtoken')
const router = express.Router();

router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    
    try {
        //check if user already exist
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' })
        }
        //Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        user = new User({
            name,
            email,
            password: hashedPassword,
        });
        await user.save();
        res.status(201).json({ message: 'User created successfully' })
    }
    catch (error) {
        console.error("Signup Error:", error.message);
        res.status(500).json({ message: 'Server error' });
    }
})
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        //Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });

        }
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' })
        }
        const payload = {
            user: {
                id: user.id,
                // password:user.password
            },
        };
        jwt.sign(
            payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
                if (err) throw err;
                res.json({ token });
            });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' })
    }
})
module.exports = router;
