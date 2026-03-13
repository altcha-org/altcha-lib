import { NestFactory } from '@nestjs/core';
import {
	Module,
	Controller,
	Post,
	Body,
	MiddlewareConsumer,
	NestModule,
	Catch,
	ExceptionFilter,
	ArgumentsHost,
	HttpException,
	HttpStatus,
} from '@nestjs/common';
import type { Response } from 'express';
import cookieParser from 'cookie-parser';

import {
	AltchaModule,
	Altcha,
	CappedMap,
	createAltchaMiddleware,
	deriveHmacKeySecret,
	randomInt,
	type AltchaResult,
} from 'altcha-lib/frameworks/nestjs';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const HMAC_SECRET = 'secret.key';

@Catch()
class GlobalExceptionFilter implements ExceptionFilter {
	catch(error: unknown, host: ArgumentsHost) {
		const ctx = host.switchToHttp();
		const res = ctx.getResponse<Response>();

		if (error instanceof HttpException) {
			console.error(error.cause);
			res.status(error.getStatus()).json({
				statusCode: error.getStatus(),
				message: error.message,
			});
			return;
		}

		console.error(error);
		res.status(HttpStatus.INTERNAL_SERVER_ERROR).send('Internal Server Error.');
	}
}

@Controller()
class SubmitController {
	@Post('submit')
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
				setCookie: {
					name: 'altcha',
					path: '/',
				},
				store: new CappedMap<string, boolean>({
					maxSize: 1_000,
				}),
			}),
		}),
	],
	controllers: [SubmitController],
})
class AppModule implements NestModule {
	// Mount the ALTCHA middleware on /submit for automatic verification
	configure(consumer: MiddlewareConsumer) {
		consumer.apply(createAltchaMiddleware()).forRoutes('submit');
	}
}

const app = await NestFactory.create(AppModule);

app.enableCors();
app.use(cookieParser());
app.useGlobalFilters(new GlobalExceptionFilter());

await app.listen(3000);
console.log('Server running on http://localhost:3000');
