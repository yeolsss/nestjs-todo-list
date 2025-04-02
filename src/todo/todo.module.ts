import { Module } from '@nestjs/common';
import { TodoService } from './todo.service';
import { TodoController } from './todo.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Todo } from './entity/todo.entity';
import { User } from 'src/user/entity/user.entity';
import { AuthModule } from 'src/auth/auth.module';
import { TodoDetail } from './entity/todo-detail.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Todo, User, TodoDetail]),
    AuthModule, // AuthModule 가져오기
  ],
  controllers: [TodoController],
  providers: [TodoService],
})
export class TodoModule {}
