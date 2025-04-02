import { Exclude } from 'class-transformer';
import { BaseTable } from './../../comm/entity/base.entity';
import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Todo } from 'src/todo/entity/todo.entity';

@Entity()
export class User extends BaseTable {
  @PrimaryGeneratedColumn()
  @Exclude({
    toPlainOnly: true,
  })
  id: number;

  @Column({
    unique: true,
  })
  email: string;

  @Column()
  @Exclude({
    toPlainOnly: true,
  })
  password: string;

  @OneToMany(() => Todo, (todo) => todo.user)
  todo: Todo[];
}
