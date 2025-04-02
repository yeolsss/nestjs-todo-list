import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateTodoDto {
  @IsNotEmpty()
  @IsString()
  title: string;

  @IsBoolean()
  @IsOptional()
  isDone?: boolean;

  @IsNotEmpty()
  @IsString()
  detail: string;

  @IsString()
  @IsOptional()
  email?: string;
}
