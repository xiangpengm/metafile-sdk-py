from sqlalchemy.orm import Session

from metafile_sdk.model.base import MetaFileTask, MetaFileTaskChunk


class OrmBase():

    def __init__(self, session):
        self.session: Session = session

    def save(self, instant):
        self.session.add(instant)
        self.session.commit()


class MetaFileTaskOrm(OrmBase):

    def get_or_create(self, file_id, defaults=None):
        if defaults is None:
            defaults = {}
        instant = self.session.query(MetaFileTask).filter(
            MetaFileTask.file_id==file_id
        ).first()
        if instant:
            return instant
        else:
            instant = MetaFileTask(**defaults)
            self.save(instant)
            return instant


class MetaFileTaskChunkOrm(OrmBase):

    def get_or_create(self, file_id, chunk_index, defaults=None):
        if defaults is None:
            defaults = {}
        instant = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.chunk_index==chunk_index
        ).first()
        if instant:
            return instant
        else:
            instant = MetaFileTaskChunk(**defaults)
            self.save(instant)
            return instant