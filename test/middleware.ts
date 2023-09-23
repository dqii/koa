import Koa from "koa"
import { Context } from "koa"
import body from "koa-body"
import { generateKeyPair } from "crypto"
import nock from "nock"
import { v4 as uuid } from "uuid"
import { initAuth } from "../src"
import jwt from "jsonwebtoken"
import { InternalOrgMemberInfo, InternalUser, TokenVerificationMetadata, toUser } from "@propelauth/node"

const AUTH_URL = "https://auth.example.com"
const ALGO = "RS256"

const app = new Koa()

app.use(body());

app.use(async (ctx: Context) => {
    if (ctx.request.method === "POST") {
        ctx.body = {
            message: "Hello World",
        }
    } else {
        ctx.status = 404
    }
})

app.listen(3000, () => {
    console.log("Server running on port 3000")
})

afterEach(() => {
    jest.useRealTimers()
})

test("bad authUrl is rejected", async () => {
    expect(() => {
        initAuth({
            authUrl: "not.a.url",
            apiKey: "apiKey",
        })
    }).toThrow()
})