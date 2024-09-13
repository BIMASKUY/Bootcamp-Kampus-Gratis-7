import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
    email: string,
    password: string
}

const userSchema = new Schema({
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
}, {
    timestamps: true
});

export const User = mongoose.model<IUser>('User', userSchema);