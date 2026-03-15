import { Router } from "express";
import { getMeController, loginController, refreshTokenController, registerController } from "../controllers/auth.controller.js";

const authRouter = Router()

/**
 * POST /api/auth/register
 */
authRouter.post("/register", registerController)

/**
 * POST /api/auth/login
 */
authRouter.post("/login", loginController)

/**
 * GET /api/auth/get-me
 */
authRouter.get("/get-me", getMeController)

/**
 * GET /api/auth/refresh-token
 */
authRouter.get("/refresh-token", refreshTokenController)

export default authRouter