import { PaddleState } from "./enum/GameEnum";
import * as Box2D from "../Box2D";
import { GameSkill } from "./GameSkill.js";

export class GameUser{
  public directionButton : PaddleState = PaddleState.STOP;
  public directionReverse : Boolean = false;
  public paddle : Box2D.Body;
  public skill : GameSkill;
  
  constructor (paddle: Box2D.Body){
    this.paddle = paddle;
    this.skill = new GameSkill();
  }
}