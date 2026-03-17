import { Router } from "express";
import { getMeController, loginController, logoutAllController, logoutController, refreshTokenController, registerController } from "../controllers/auth.controller.js";

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

/**
 * GET /api/auth/logout
 */
authRouter.get("/logout", logoutController)


/**
 * GET /api/auth/logout-all
 */
authRouter.get("/logout-all", logoutAllController)

export default authRouter