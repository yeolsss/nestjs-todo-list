import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entity/user.entity';
import { DataSource, Repository } from 'typeorm';
import { Todo } from './entity/todo.entity';
import { TodoDetail } from './entity/todo-detail.entity';

@Injectable()
export class TodoService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Todo)
    private readonly todoRepository: Repository<Todo>,
    @InjectRepository(TodoDetail)
    private readonly todoDetailRepository: Repository<TodoDetail>,
    private readonly dataSource: DataSource,
  ) {}

  async findAll(email: string, title?: string) {
    const qb = await this.todoRepository
      .createQueryBuilder('todo')
      .leftJoinAndSelect('todo.detail', 'todo_detail')
      .leftJoinAndSelect('todo.user', 'user')
      .where('user.email = :email', { email })
      .orderBy('todo.isDone', 'ASC') // false가 먼저 오도록 ASC 정렬 (false는 0, true는 1이므로)
      .addOrderBy('todo.createAt', 'DESC'); // 각 그룹 내에서 최신순으로 정렬

    if (title) {
      qb.andWhere('todo.title LIKE :title', { title: `%${title}%` });
    }

    const [todos, count] = await qb.getManyAndCount();

    // Count todos by isDone status
    const completedCount = todos.filter((todo) => todo.isDone).length;

    return {
      todos,
      count,
      completedCount,
    };
  }

  async findOne(email: string, id: number) {
    const todo = await this.todoRepository.findOne({
      where: { id, user: { email } },
      relations: ['detail'],
    });

    if (!todo) {
      throw new NotFoundException(`검색된 할 일이 없습니다.`);
    }

    return todo;
  }

  async create(email: string, createTodoDto: CreateTodoDto) {
    const userId = await this.userRepository.findOne({ where: { email } });
    const newTodo = this.todoRepository.create({
      title: createTodoDto.title,
      isDone: false,
      detail: { detail: createTodoDto.detail },
      user: { id: userId.id },
    });

    return await this.todoRepository.save(newTodo);
  }

  async update(email: string, id: number, updateTodoDto: UpdateTodoDto) {
    const todo = await this.findOne(email, id);

    const qr = this.dataSource.createQueryRunner();
    await qr.connect();
    await qr.startTransaction();

    try {
      const { detail, ...todoRest } = updateTodoDto;

      const todoUpdateFields = {
        ...todoRest,
      };

      await qr.manager
        .createQueryBuilder()
        .update(Todo)
        .set(todoUpdateFields)
        .where('id = :id', { id })
        .execute();

      if (detail) {
        await qr.manager
          .createQueryBuilder()
          .update(TodoDetail)
          .set({ detail })
          .where('id = :id', { id: todo.detail.id })
          .execute();
      }

      await qr.commitTransaction();
      return this.findOne(email, id);
    } catch (e) {
      await qr.rollbackTransaction();
      throw e;
    } finally {
      await qr.release();
    }
  }
  async remove(email: string, id: number) {
    await this.findOne(email, id);

    await this.todoRepository.delete(id);
    return id;
  }
  async toggle(email: string, id: number) {
    const todo = await this.findOne(email, id);
    const updatedTodo = await this.todoRepository.save({
      ...todo,
      isDone: !todo.isDone,
    });

    return updatedTodo;
  }
}
