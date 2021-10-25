from sqlalchemy.orm import Session

from metafile_sdk.model.base import MetaFileTask, MetaFileTaskChunk, EnumMetaFileTask


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

    def find_doing_chunk_by_number(self, file_id, number=5):
        instant_list = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status!=EnumMetaFileTask.success
        ).limit(number)
        return list(instant_list)

    def is_all_success(self, file_id):
        instant = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status!=EnumMetaFileTask.success
        ).first()
        return instant is None

    def find_no_sync_metafile_chunk(self, file_id, number=5):
        instant_list = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status==EnumMetaFileTask.success,
            MetaFileTaskChunk.is_sync_metafile==False
        ).limit(number)
        return list(instant_list)