import { Exclude } from 'class-transformer';
import { CreateDateColumn, UpdateDateColumn, VersionColumn } from 'typeorm';

export class BaseTable {
  @CreateDateColumn()
  @Exclude()
  createAt: Date;

  @UpdateDateColumn()
  @Exclude()
  updateAt: Date;

  @VersionColumn()
  @Exclude()
  version: number;
}
