import { create, verify } from 'https://deno.land/x/djwt@v2.4/mod.ts'
import { Application, Router } from 'https://deno.land/x/oak/mod.ts'
import User from './interfaces/User.ts'

const key = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"],
);

const adminUser = { email: "test@test.com", password: "password"};
const validUsers: Array<{email: string, password: string}> = [adminUser]
let currentUser: JsonWebKey;

const router = new Router();
router
	.get("/", async (context) => {
		context.response.body = await Deno.readFile(`${Deno.cwd()}/public/index.html`);
	})
	.get("/login", (context) => {
		if (currentUser) {
			context.response.body = currentUser;
		} else {
			context.response.body = "Not currently logged in..."
		}
	})
	.post("/login", async (context) => {
		const loginCredentials = await validateCredentials();

		async function validateCredentials(): Promise<User | void> {
			const { value } = context.request.body({type: 'form'});
			const tempCredentials = {email: '', password: '', admin: false}
			let validateduser = false;
			await value.then((result) => {
				result.forEach((value, keyName) => {
					if (keyName === 'email') {
						tempCredentials.email = value
					} else if (keyName === 'password') {
						tempCredentials.password = value
					}
				})
			}).catch(error => error);

			validUsers.forEach((validUser) => {
				if(validUser.email === tempCredentials.email && validUser.password === tempCredentials.password) {
					validateduser = true;
				}
			})

			if (validateduser) {
				if(tempCredentials.email === adminUser.email && tempCredentials.password === adminUser.password) {
					tempCredentials.admin = true
				}
				return tempCredentials;
			}
		}

		if (loginCredentials) {
			const jwt = await create({alg: "HS512", type: "JWT"}, { email: loginCredentials.email, admin: loginCredentials.admin }, key)
			const verifyPayload = await verify(jwt, key);
			console.log('the payload is verified', verifyPayload);
			context.response.body = jwt
		} else {
			context.response.body = "Invalid user credentials";
		}
	});

const HOST = 'localhost';
const PORT = 8000;

const app = new Application();

app.use(router.routes());
app.use(router.allowedMethods());

console.log(`Listening on port: ${PORT}`);

await app.listen(`${HOST}:${PORT}`);
