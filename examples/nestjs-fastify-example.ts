import { NestFactory } from '@nestjs/core';
import {
	Module,
	Controller,
	Post,
	Body,
	UseGuards,
	Catch,
	ExceptionFilter,
	ArgumentsHost,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import {
	FastifyAdapter,
	NestFastifyApplication,
} from '@nestjs/platform-fastify';
import type { FastifyReply } from 'fastify';

import {
	AltchaModule,
	Altcha,
	CappedMap,
	createAltchaGuard,
	deriveHmacKeySecret,
	randomInt,
	type AltchaResult,
} from 'altcha-lib/frameworks/nestjs';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const HMAC_SECRET = 'secret.key';

@Catch()
class GlobalExceptionFilter implements ExceptionFilter {
	catch(error: unknown, host: ArgumentsHost) {
		const reply = host.switchToHttp().getResponse<FastifyReply>();

		if (error instanceof HttpException) {
			reply.status(error.getStatus()).send({
				statusCode: error.getStatus(),
				message: error.message,
			});
			return;
		}

		console.error(error);
		reply
			.status(HttpStatus.INTERNAL_SERVER_ERROR)
			.send('Internal Server Error.');
	}
}

@Controller()
class SubmitController {
	// On the Fastify adapter use the guard, not the middleware: Fastify middleware
	// runs before the body is parsed, so a body-delivered payload would be invisible.
	@Post('submit')
	@UseGuards(createAltchaGuard())
	async submit(
		@Altcha() altcha: AltchaResult | undefined,
		@Body() body: Record<string, unknown>
	) {
		return {
			altcha,
			body,
		};
	}
}

@Module({
	imports: [
		AltchaModule.registerAsync({
			useFactory: async () => ({
				hmacSignatureSecret: HMAC_SECRET,
				hmacKeySignatureSecret: await deriveHmacKeySecret(HMAC_SECRET),
				createChallengeParameters: () => ({
					algorithm: 'PBKDF2/SHA-256' as const,
					cost: 5_000,
					counter: randomInt(5_000, 10_000),
					expiresAt: new Date(Date.now() + 600_000), // 10 minutes
				}),
				deriveKey,
				// setCookie: {
				// 	name: 'altcha',
				// 	path: '/',
				// },
				store: new CappedMap<string, boolean>({
					maxSize: 1_000,
				}),
			}),
		}),
	],
	controllers: [SubmitController],
})
class AppModule {}

const app = await NestFactory.create<NestFastifyApplication>(
	AppModule,
	new FastifyAdapter()
);

app.enableCors();
app.useGlobalFilters(new GlobalExceptionFilter());

await app.listen(3000, '0.0.0.0');
console.log('Server running on http://localhost:3000');
