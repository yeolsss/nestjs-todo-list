import { BaseTable } from 'src/comm/entity/base.entity';
import { User } from 'src/user/entity/user.entity';
import {
  Column,
  Entity,
  JoinColumn,
  ManyToOne,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { TodoDetail } from './todo-detail.entity';

@Entity()
export class Todo extends BaseTable {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  title: string;

  @Column()
  isDone: boolean;

  @OneToOne(() => TodoDetail, (todoDetail) => todoDetail.id, {
    cascade: true,
    nullable: false,
  })
  @JoinColumn()
  detail: TodoDetail;

  @ManyToOne(() => User, (user) => user.id, {
    nullable: false,
  })
  user: User;
}
