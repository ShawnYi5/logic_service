from sqlalchemy import Column, String, Integer, DateTime, create_engine, BigInteger, Text, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLLITE_DICT_DB_PATH = '/var/db/media.db'

Base = declarative_base()
# 初始化数据库连接:
engine = create_engine("sqlite:///{}?check_same_thread=False".format(SQLLITE_DICT_DB_PATH))
# 创建DBSession类型:
DBSession = sessionmaker(bind=engine)


class Manager(object):

    def __init__(self, model):
        self._session = DBSession()
        self._model = model

    def create(self, **kwargs):
        ins = self._model(**kwargs)
        self._session.add(ins)
        self._session.commit()
        return ins

    def filter(self, *criterion):
        return self._session.query(self._model).filter(*criterion)

    def get(self, *criterion):
        query_set = self._session.query(self._model).filter(*criterion)
        if query_set.count() != 1:
            raise Exception('not fond instance:{}'.format(*criterion))
        return query_set[0]


class MediaTaskRecord(Base):
    __tablename__ = 'task_record'

    id = Column(Integer, primary_key=True)
    # Task的uuid
    task_uuid = Column(String(256), unique=True)
    # 产生日期
    production_date = Column(DateTime())
    # 媒体库的uuid
    media_uuid = Column(String(256))
    # task扩展信息
    task_ext_inf = Column(Text())
    # task占据媒体大小
    occupy_size = Column(BigInteger(), default=0)
    # 总共分卷的文件数。
    file_count = Column(BigInteger(), default=0)
    # 删除标记
    deleting = Column(Boolean(), default=False)
    # 是否成功
    successful = Column(Boolean(), default=False)
    # 是否已经过期被覆盖或被删除。
    overwritedata = Column(Boolean(), default=False)

    def save(self):
        self.objects._session.commit()

    def delete(self):
        self.objects._session.delete(self)
        self.save()


MediaTaskRecord.objects = Manager(MediaTaskRecord)

if __name__ == '__main__':
    import uuid
    import datetime
    import json

    rev = MediaTaskRecord.objects.create(
        task_uuid=uuid.uuid4().hex,
        production_date=datetime.datetime.now(),
        media_uuid=uuid.uuid4().hex,
        task_ext_inf='task_ext_inf'
    )

    print(rev.id)
    print(rev.successful)
    rev.successful = True
    rev.save()  # 更新

    rev = MediaTaskRecord.objects.get(MediaTaskRecord.id == 2)
    rev.delete()  # 删除
