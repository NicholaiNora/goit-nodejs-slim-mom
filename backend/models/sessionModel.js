import { Schema, model } from "mongoose";

const sessionSchema = new Schema(
  {
    uid: {
      type: Schema.Types.ObjectId,
      ref: "user",
      required: true,
    },
    token: {
      type: String,
      default: null,
    },
  },
  { versionKey: false }
);

const Session = model("session", sessionSchema);

export { Session };
