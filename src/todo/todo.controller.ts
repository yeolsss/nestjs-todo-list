import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
  Query,
  UseInterceptors,
  ClassSerializerInterceptor,
} from '@nestjs/common';
import { TodoService } from './todo.service';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';

@Controller('todos')
@UseInterceptors(ClassSerializerInterceptor)
export class TodoController {
  constructor(private readonly todoService: TodoService) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll(@Req() req, @Query('title') title?: string) {
    const email = req.user.email; // JWT 가드에서 설정한 사용자 정보 사용
    return this.todoService.findAll(email, title);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Req() req, @Param('id') id: string) {
    const email = req.user.email;
    return this.todoService.findOne(email, +id);
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  create(@Req() req, @Body() createTodoDto: CreateTodoDto) {
    const email = req.user.email;
    return this.todoService.create(email, createTodoDto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  update(
    @Req() req,
    @Param('id') id: string,
    @Body() updateTodoDto: UpdateTodoDto,
  ) {
    const email = req.user.email;
    return this.todoService.update(email, +id, updateTodoDto);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  remove(@Req() req, @Param('id') id: string) {
    const email = req.user.email;
    return this.todoService.remove(email, +id);
  }
}
