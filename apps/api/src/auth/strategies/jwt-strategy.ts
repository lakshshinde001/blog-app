import { ConfigService } from "@nestjs/config"
import { PassportStrategy } from "@nestjs/passport"
import { ExtractJwt, Strategy } from "passport-jwt"
import { AuthJwtPayload } from "../types/auth-jwtPayload"
import { AuthService } from "../auth.service"
import { Injectable, UnauthorizedException } from "@nestjs/common"

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get<string>('JWT_SECRET', 'default-secret'),
      ignoreExpiration: false,
    });
  }

  async validate(payload: AuthJwtPayload) {
    const userId = payload.sub;
    
    // Ensure validateJwtUser returns the user
    const user = await this.authService.validateJwtUser(userId);

    if (!user) {
      throw new UnauthorizedException("Invalid JWT Token");
    }

    return user; // ✅ This must return user data
  }
}