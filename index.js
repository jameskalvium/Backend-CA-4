const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const cookieParser = require("cookie-parser")
require("dotenv").config()
app.use(express.json())
app.use(cookieParser())
const PORT = 8000;

mongoose
    .connect(process.env.MONGO_URL)
    .then(()=>console.log("MONGO db connected successfully"))
    .catch(err=> console.error(err))


const userSchema = new mongoose.Schema({
    email: {type: String, required: true},
    password :{type: String}
})

const User = mongoose.model("User",userSchema)

app.post("/register",async(req,res)=>{
    const {email,password} = req.body;
    if(!email || !password){
        return res.status(401).json({message:"All the fields should be true"})
    }
    try{
        let user = User.findOne({email})
        if(!user){
            return res.status(404).json({message:"user not found"})
        }else{
            const isMatch = bcrypt.compare(password,user.password)
            if(!isMatch){
                return res.status(400).json({message:"invalid credentials"})
            }else{
            const hashedpassword = bcrypt.hash(password,10)
            user = {email, password:hashedpassword}
            await user.save
            }
        }
        const accesstoken = jwt.sign({email,password},process.env.secretkey,{expiresIn:"1000*60*60*15"})
        const refreshtoken = jwt.sign({email,password},process.env.secretkey,{expiresIn:"1d"})
        res.cookie("auth_token",accesstoken,{httpOnly:true})
        res.cookie("auth_token",refreshtoken,{httpOnly:true})
        res.json({message:"Authentication successfull"})
    }
    catch(err){
        return res.status(500).json({message:"Internal server error",error:err.message})
    }
})

app.get("/refreshToken",(req,res)=>{
    if(!refreshtoken){
        const newaccesstoken = jwt.sign({email,password},process.env.secretkey,{expiresIn:"15m"})
        res.cookie("auth_token",newaccesstoken,{httpOnly:true})
        res.json({message:"new token created"})
    }

})

app.listen(PORT,()=>console.log("The server is running on http://localhost:8000"))