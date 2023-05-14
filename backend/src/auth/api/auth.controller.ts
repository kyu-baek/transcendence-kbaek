import { Body, Controller, Get, Header, Post, Query, Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../../models/user/entities';
import { Repository } from 'typeorm';
import { FtGuard } from '../../common/guards/ft/ft.guard';
import { AuthService } from './services';
import { Request, Response } from 'express';
import { TwoFactorGuard } from '../../common/guards/twoFactor/twoFactor.guard';
import { GetGuardData } from '../../common/decorators';
import { JwtGuard } from '../../common/guards/jwt/jwt.guard';
import { TokenDto } from '../otp/token.dto';
import { FtDataInterface } from '../../common/interfaces/FtData.interface';
import { JwtPayloadInterface } from '../../common/interfaces/JwtUser.interface';
import { EmailReqDto } from '../../models/user/api/dtos/verifyEmailReq.dto';
import { VerifyEmailToken } from '../../models/user/api/dtos/verifyEmailToken.dto';
import { KakaoGuard } from 'src/common/guards/kakao/kakao.guard';


interface IOAuthUser {
  user: {
    name: string;
    email: string;
    password: string;
  };
}

@Controller('auth')
export class AuthController {
  constructor(@InjectRepository(User) private userRepository: Repository<User>, private authService: AuthService) {}

  // will be redirected to /auth/redirect/42
  @UseGuards(FtGuard)
  @Get('/signin/42')
  signIn() {
    return;
  }

  // will be redirected to front
  @UseGuards(FtGuard)
  @Get('/redirect/42')
  async ftRedirect(@GetGuardData() data: FtDataInterface, @Res() res: Response): Promise<void> {
    try {
      return await this.authService.redirect(data, res);
    } catch (e) {
      if (e instanceof UnauthorizedException) {
        res.redirect('/signin_duplicated');
      } else {
        res.redirect('/signin_fail');
      }
    }
  }

  // will be redirected to /
  @UseGuards(JwtGuard)
  @Get('/signout')
  signOut(@Res() res: Response): void {
    // client have to disconnect socket
    return this.authService.signOut(res);
  }

  // will be redirected to /
  @UseGuards(TwoFactorGuard)
  @Post('/2fa/otp')
  async validateOtp(
    @GetGuardData() data: JwtPayloadInterface,
    @Body() payload: TokenDto,
    @Res() res: Response
  ): Promise<void> {
    return await this.authService.validateOtp(data.user_id, payload.token, res);
  }


  /* 
    email login
  */
  @Post('/signin/email')
  async verifyEmail(
    @Body() payload: EmailReqDto,
    @Res() res: Response
  ): Promise<void> {
    return await this.authService.verifyEmail(payload.email, res);
  }


  @Post('/emailVerify')
  async confirmEmail(
    @Body() dto: VerifyEmailToken,
    @Res() res: Response
  ){
    return await this.authService.confirmEmailToken(dto, res);
  }

  /* 카카오 로그인 */

  @Get('kakaoLogin')
  @Header('Content-Type', 'text/html')
  getKakaoLoginPage(): string {
    return `
      <div>
        <h1>카카오 로그인</h1>
        <form action="/kakaoLoginLogic" method="GET">
          <input type="submit" value="카카오로그인" />
        </form>
        <form action="/kakaoLogout" method="GET">
          <input type="submit" value="카카오로그아웃 및 연결 끊기" />
        </form>
      </div>
    `;
  }


  
  
  @UseGuards(KakaoGuard)
  @Get("/redirect/kakao")
  async loginKakao(
    @GetGuardData() data: FtDataInterface,
    @Res() res: Response
  ) {
    // this.authService.OAuthLogin({ req, res });

    try {
      return await this.authService.redirect(data, res);
    } catch (e) {
      if (e instanceof UnauthorizedException) {
        res.redirect('/signin_duplicated');
      } else {
        res.redirect('/signin_fail');
      }
    }
  }

  // /* 구글 로그인 */
  // @UseGuards(AuthGuard("google"))
  // @Get("/signin/google")
  // async loginGoogle(
  //   @Req() req: Request & IOAuthUser, //
  //   @Res() res: Response
  // ) {
  //   this.authService.OAuthLogin({ req, res });
  // }

  // /* 네이버 로그인 */
  // @UseGuards(AuthGuard("naver"))
  // @Get("/signin/naver")
  // async loginNaver(
  //   @Req() req: Request & IOAuthUser, //
  //   @Res() res: Response
  // ) {
  //   this.authService.OAuthLogin({ req, res });
  // }
  

}


