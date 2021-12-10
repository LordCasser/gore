// This file is part of GoRE.
//
// Copyright (C) 2019-2021 GoRE Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package gore

import (
	"debug/gosym"
	"debug/macho"
	"fmt"
)

func openMachO(fp string) (*machoFile, error) {
	f, err := macho.Open(fp)
	if err != nil {
		return nil, err
	}
	return &machoFile{file: f}, nil
}

type machoFile struct {
	file *macho.File
}

func (m *machoFile) getFva(off uint64) (uint64, error) {
	for _, section := range m.file.Sections {

		if uint64(section.Addr) <= off && off < uint64(section.Addr+section.Size) {
			// rva-base-rdata+rdata_raw_offset
			return off - uint64(section.Addr) + uint64(section.Offset), nil
		}
	}
	return 0, ErrSectionDoesNotExist
}

func (m *machoFile) Close() error {
	return m.file.Close()
}

func (m *machoFile) getPCLNTab() (*gosym.Table, error) {
	section := m.file.Section("__gopclntab")
	if section == nil {
		return nil, ErrNoPCLNTab
	}
	data, err := section.Data()
	if data == nil {
		return nil, err
	}
	pcln := gosym.NewLineTable(data, m.file.Section("__text").Addr)
	TypeStringOffsets.PCLnTab = section.Addr
	return gosym.NewTable(nil, pcln)
}

func (m *machoFile) getRData() ([]byte, error) {
	_, data, err := m.getSectionData("__rodata")
	return data, err
}

func (m *machoFile) getCodeSection() ([]byte, error) {
	_, data, err := m.getSectionData("__text")
	return data, err
}

func (m *machoFile) getSectionDataFromOffset(off uint64) (uint64, []byte, error) {
	for _, section := range m.file.Sections {
		if section.Offset == 0 {
			// Only exist in memory
			continue
		}

		if section.Addr <= off && off < (section.Addr+section.Size) {
			data, err := section.Data()
			return section.Addr, data, err
		}
	}
	return 0, nil, ErrSectionDoesNotExist
}

func (m *machoFile) getSectionData(s string) (uint64, []byte, error) {
	section := m.file.Section(s)
	if section == nil {
		return 0, nil, ErrSectionDoesNotExist
	}
	data, err := section.Data()
	return section.Addr, data, err
}

func (m *machoFile) getFileInfo() *FileInfo {
	fi := &FileInfo{
		ByteOrder: m.file.ByteOrder,
		OS:        "macOS",
	}
	switch m.file.Cpu {
	case macho.Cpu386:
		fi.WordSize = intSize32
		fi.Arch = Arch386
	case macho.CpuAmd64:
		fi.WordSize = intSize64
		fi.Arch = ArchAMD64
	default:
		panic("Unsupported architecture")
	}
	return fi
}

func (m *machoFile) getPCLNTABData() (uint64, []byte, error) {
	return m.getSectionData("__gopclntab")
}

func (m *machoFile) moduledataSection() string {
	return "__noptrdata"
}

func (m *machoFile) getBuildID() (string, error) {
	data, err := m.getCodeSection()
	if err != nil {
		return "", fmt.Errorf("failed to get code section: %w", err)
	}
	return parseBuildIDFromRaw(data)
}
