import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseInterceptors,
  ClassSerializerInterceptor,
  Request,
} from '@nestjs/common';
import { TodoService } from './todo.service';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';

@Controller('todos')
@UseInterceptors(ClassSerializerInterceptor)
export class TodoController {
  constructor(private readonly todoService: TodoService) {}

  @Get()
  findAll(@Request() req2, @Query('title') title?: string) {
    const email = req2.user.sub;
    return this.todoService.findAll(email, title);
  }

  @Get(':id')
  findOne(@Request() req, @Param('id') id: string) {
    const email = req.user.sub;
    return this.todoService.findOne(email, +id);
  }

  @Post()
  create(@Request() req, @Body() createTodoDto: CreateTodoDto) {
    const email = req.user.sub;
    return this.todoService.create(email, createTodoDto);
  }

  @Patch(':id')
  update(
    @Request() req,
    @Param('id') id: string,
    @Body() updateTodoDto: UpdateTodoDto,
  ) {
    const email = req.user.sub;
    return this.todoService.update(email, +id, updateTodoDto);
  }

  @Delete(':id')
  remove(@Request() req, @Param('id') id: string) {
    const email = req.user.sub;
    return this.todoService.remove(email, +id);
  }

  @Patch('toggle/:id')
  toggle(@Request() req, @Param('id') id: string) {
    const email = req.user.sub;
    return this.todoService.toggle(email, +id);
  }
}
