from threading import Lock

from sqlalchemy.orm import Session

from metafile_sdk.model.base import MetaFileTask, MetaFileTaskChunk, EnumMetaFileTask


class OrmBase(object):
    _lock = Lock()

    def __init__(self, session):
        self.session: Session = session

    def save(self, instant):
        self._lock.acquire(timeout=0.005)
        self.session.add(instant)
        self.session.commit()
        self._lock.release()

    def add(self, instant):
        self.session.add(instant)

    def commit(self):
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

    def get_by_sha256(self, sha256):
        instant = self.session.query(MetaFileTask).filter(
            MetaFileTask.sha256==sha256
        ).first()
        return instant

    def delete_instant(self, instant):
        self.session.delete(instant)
        self.session.commit()


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
            MetaFileTaskChunk.chunk_index!=0,
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status!=EnumMetaFileTask.success
        ).limit(number)
        return list(instant_list)

    # scan_chunk
    def find_no_scan_chunk_by_number(self, file_id, number=5):
        instant_list = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.chunk_index!=0,
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.scan_chunk==False
        ).limit(number)
        return list(instant_list)

    def update_no_success_tx(self, file_id):
        self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.chunk_index!=0,
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status!=EnumMetaFileTask.success,
            MetaFileTaskChunk.unspents_txid!=None,
            MetaFileTaskChunk.unspents_index!=None,
        ).update({
            "unspents_txid": None,
            "unspents_index": None,
        })
        self.commit()

    def no_success_chunks(self, file_id):
        chunks = self.session.query(MetaFileTaskChunk).filter(
                MetaFileTaskChunk.chunk_index!=0,
                MetaFileTaskChunk.file_id==file_id,
                MetaFileTaskChunk.status!=EnumMetaFileTask.success,
        ).count()
        return chunks

    def find_no_unspent_chunk(self, file_id, number=5):
        instant_list = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.chunk_index!=0,
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status!=EnumMetaFileTask.success,
            MetaFileTaskChunk.unspents_txid==None,
            MetaFileTaskChunk.unspents_index==None,
        ).limit(number)
        return list(instant_list)

    def find_all(self, file_id):
        instant_list = self.session.query(MetaFileTaskChunk).filter(
                MetaFileTaskChunk.chunk_index!=0,
                MetaFileTaskChunk.file_id==file_id
            ).all()
        return list(instant_list)

    def is_all_success(self, file_id):
        instant = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status!=EnumMetaFileTask.success
        ).first()
        return instant is None

    def find_no_sync_metafile_chunk(self, file_id, number=5):
        instant_list = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.chunk_index!=0,
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.status==EnumMetaFileTask.success,
            MetaFileTaskChunk.is_sync_metafile==False
        ).limit(number)
        return list(instant_list)

    def is_all_chunk_sync(self, file_id):
        instant = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.chunk_index!=0,
            MetaFileTaskChunk.file_id==file_id,
            MetaFileTaskChunk.is_sync_metafile==False
        ).first()
        return instant is None

    def is_index_chunk_async(self, file_id):
        instant = self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.chunk_index==0,
            MetaFileTaskChunk.file_id==file_id
        ).first()
        if instant is None:
            return False
        else:
            instant: MetaFileTaskChunk
            if instant.is_sync_metafile:
                return True
            else:
                return False

    def delete_by_file_id(self, file_id):
        self.session.query(MetaFileTaskChunk).filter(
            MetaFileTaskChunk.file_id==file_id
        ).delete()
        self.session.commit()
